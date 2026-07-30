package alert

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"synsec/internal/store"
)

// Following the journal.
//
// One reader, one cursor, and every surface covered: the browser writes a
// line, so does the API, so does the command line running in a completely
// separate process while the service is stopped. When the service comes back
// it reads what it missed and says so. Wiring a notifier into the handlers
// would have covered the first two and quietly missed the third, which is the
// one somebody would use if they were up to no good.

const (
	// cursorKey remembers how far the log has been read. Plain, not sealed:
	// it is a row number, and the alert has to keep working when the vault is
	// sealed enough to read it.
	cursorKey = "alert_cursor"

	pollEvery  = 2 * time.Second
	flushAfter = 10 * time.Second
	// muteFor is how long a kind stays quiet after being sent. A scan makes
	// thousands of refusals in a minute; this turns them into one message a
	// minute carrying the count, which is the same information and a phone
	// that still works afterwards.
	muteFor = time.Minute
	// dailyCap bounds what a single day can send, whatever happens. Reached,
	// the watcher says so once and goes quiet: an alerting system that floods
	// is one that gets muted at the receiving end, permanently.
	dailyCap  = 200
	batchSize = 500
	// maxRounds bounds one catching-up pass at fifty thousand lines. Past
	// that the rest waits two seconds, which keeps a runaway writer from
	// pinning this loop while the journal grows underneath it.
	maxRounds = 100
)

// Config is what the watcher reads before each pass, so an edit in the
// interface takes effect without a restart.
type Config struct {
	Enabled bool
	Level   Severity
	Webhook Webhook
}

// Status is what the settings page shows: did the last message get through,
// and if not, why.
type Status struct {
	LastAttempt time.Time
	LastSuccess time.Time
	LastError   string
	Sent        int
	Failed      int
	Capped      bool
}

// Watcher follows the journal and sends what matters.
type Watcher struct {
	db     *store.DB
	config func(context.Context) (Config, error)

	now  func() time.Time
	poll time.Duration

	mu        sync.Mutex
	status    Status
	pending   map[string]*Event
	oldest    time.Time
	mutedTil  map[Kind]time.Time
	sentDay   time.Time
	sentToday int

	// vaults caches vault names, so a burst on one secret does not become a
	// burst of queries.
	vaults map[string]string
}

// NewWatcher builds one. config is called before each pass rather than kept,
// because the address and the level can change while the server runs.
func NewWatcher(db *store.DB, config func(context.Context) (Config, error)) *Watcher {
	return &Watcher{
		db:       db,
		config:   config,
		now:      time.Now,
		poll:     pollEvery,
		pending:  make(map[string]*Event),
		mutedTil: make(map[Kind]time.Time),
		vaults:   make(map[string]string),
	}
}

// Status reports what happened lately.
func (w *Watcher) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

// Run follows the log until the context is cancelled.
func (w *Watcher) Run(ctx context.Context) {
	if err := w.start(ctx); err != nil {
		w.note(err)
	}

	ticker := time.NewTicker(w.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.pass(ctx); err != nil && !errors.Is(err, context.Canceled) {
				w.note(err)
			}
		}
	}
}

// start places the cursor at the end of the log the first time.
//
// An installation that turns this on after a year must not announce that year.
// What happened before somebody asked to be told is history, not news.
func (w *Watcher) start(ctx context.Context) error {
	raw, err := w.db.ServerSetting(ctx, cursorKey, "")
	if err != nil {
		return err
	}
	if raw != "" {
		return nil
	}
	last, err := w.db.LastAuditID(ctx)
	if err != nil {
		return err
	}
	return w.db.SetServerSetting(ctx, cursorKey, strconv.FormatInt(last, 10))
}

// pass reads what is new, folds it, and sends what is due.
func (w *Watcher) pass(ctx context.Context) error {
	cfg, err := w.config(ctx)
	if err != nil {
		return err
	}

	raw, err := w.db.ServerSetting(ctx, cursorKey, "0")
	if err != nil {
		return err
	}
	cursor, _ := strconv.ParseInt(raw, 10, 64)

	// Read until the log is caught up, not just one page of it. A scan writes
	// thousands of lines in a few seconds; stopping at the first page would
	// send one message per page, which is the flood this whole file exists to
	// prevent. Bounded all the same, so a pass cannot run forever while the
	// log keeps growing under it.
	var read int
	for round := 0; round < maxRounds; round++ {
		entries, err := w.db.AuditSince(ctx, cursor, batchSize)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			break
		}
		next, err := w.absorb(ctx, entries, cfg)
		if err != nil {
			return err
		}
		cursor = next
		read += len(entries)
		if len(entries) < batchSize {
			break
		}
	}

	if read > 0 {
		if err := w.db.SetServerSetting(ctx, cursorKey, strconv.FormatInt(cursor, 10)); err != nil {
			return err
		}
	}
	return w.flush(ctx, cfg)
}

// absorb takes one page of the log and returns the cursor it reached.
func (w *Watcher) absorb(ctx context.Context, entries []store.AuditEntry, cfg Config) (int64, error) {
	var cursor int64
	for _, e := range entries {
		cursor = e.ID
		// Addresses are remembered whether or not anybody is listening.
		// Otherwise switching alerts on would announce every address the
		// server has ever seen, all at once, and teach the owner on day one
		// that these messages are noise.
		status, err := w.db.NoteAddress(ctx, e.ActorKind, e.ActorID, e.IP, e.At)
		if err != nil {
			return cursor, err
		}
		if !cfg.Enabled {
			continue
		}
		if status == store.AddressNew {
			w.hold(w.event(ctx, e, rule{KindNewAddress, SeverityInfo,
				"Adresse jamais vue pour ce compte ou cet appareil"}), cfg.Level)
		}
		if r, ok := classify(e); ok {
			w.hold(w.event(ctx, e, r), cfg.Level)
		}
	}
	return cursor, nil
}

// event fills in what the journal knows plus the vault's name.
func (w *Watcher) event(ctx context.Context, e store.AuditEntry, r rule) Event {
	return Event{
		Kind:      r.kind,
		Severity:  r.sev.String(),
		sev:       r.sev,
		At:        e.At,
		Summary:   r.summary,
		Actor:     e.ActorLabel,
		ActorKind: e.ActorKind,
		Vault:     w.vaultName(ctx, e.ProjectID),
		Target:    e.Target,
		IP:        e.IP,
		Detail:    e.Detail,
		Count:     1,
	}
}

func (w *Watcher) vaultName(ctx context.Context, projectID string) string {
	if projectID == "" {
		return ""
	}
	if name, ok := w.vaults[projectID]; ok {
		return name
	}
	p, err := w.db.Project(ctx, projectID)
	if err != nil {
		return ""
	}
	w.vaults[projectID] = p.Name
	return p.Name
}

// hold buffers an event, folding it into an identical one already waiting.
func (w *Watcher) hold(e Event, level Severity) {
	if e.sev < level {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	key := string(e.Kind) + "\x00" + e.Actor + "\x00" + e.Vault + "\x00" + e.Target + "\x00" + e.IP
	if held, ok := w.pending[key]; ok {
		held.Count++
		held.At = e.At // the most recent occurrence, which is the useful one
		return
	}
	if w.oldest.IsZero() {
		w.oldest = w.now()
	}
	w.pending[key] = &e
}

// flush sends what is waiting, if anything is due.
func (w *Watcher) flush(ctx context.Context, cfg Config) error {
	now := w.now()

	w.mu.Lock()
	if len(w.pending) == 0 || now.Sub(w.oldest) < flushAfter {
		w.mu.Unlock()
		return nil
	}

	var ready []Event
	for key, e := range w.pending {
		if until, muted := w.mutedTil[e.Kind]; muted && now.Before(until) {
			continue // keeps accumulating, goes out when the mute expires
		}
		ready = append(ready, *e)
		delete(w.pending, key)
	}
	if len(w.pending) == 0 {
		w.oldest = time.Time{}
	} else {
		w.oldest = now // the rest waits a full window rather than retrying every tick
	}
	if len(ready) == 0 {
		w.mu.Unlock()
		return nil
	}
	for _, e := range ready {
		w.mutedTil[e.Kind] = now.Add(muteFor)
	}

	capped, ceiling := w.chargeLocked(now, len(ready))
	w.mu.Unlock()

	if ceiling {
		// Said once, so the silence that follows is explained rather than
		// mistaken for calm.
		ready = []Event{{
			Kind: "alert.capped", Severity: SeverityWarning.String(), sev: SeverityWarning,
			At: now, Count: 1,
			Summary: "Plafond de messages atteint : SYNSEC arrête d'envoyer jusqu'à demain. Le journal, lui, continue.",
		}}
	} else if capped {
		return nil
	}

	err := cfg.Webhook.send(ctx, message{
		Server: cfg.Webhook.Server,
		SentAt: now,
		Events: ready,
	})
	w.record(now, err)
	return err
}

// chargeLocked counts a send against the daily ceiling. It reports whether
// sending is barred, and whether this is the moment the ceiling was reached.
func (w *Watcher) chargeLocked(now time.Time, n int) (barred, justReached bool) {
	day := now.Truncate(24 * time.Hour)
	if !w.sentDay.Equal(day) {
		w.sentDay = day
		w.sentToday = 0
		w.status.Capped = false
	}
	if w.sentToday >= dailyCap {
		return true, false
	}
	w.sentToday += n
	if w.sentToday >= dailyCap {
		w.status.Capped = true
		return true, true
	}
	return false, false
}

// Test sends a message somebody asked for, past the mute and the ceiling.
//
// A configuration that cannot be tried is one nobody trusts, and the day it is
// needed is the wrong day to find out the address had a typo in it.
func (w *Watcher) Test(ctx context.Context, cfg Config) error {
	now := w.now()
	err := cfg.Webhook.send(ctx, message{
		Server: cfg.Webhook.Server,
		SentAt: now,
		Test:   true,
		Events: []Event{{
			Kind: "alert.test", Severity: SeverityInfo.String(), sev: SeverityInfo,
			At: now, Count: 1,
			Summary: "Message de test envoyé depuis SYNSEC. Si tu lis ceci, les alertes arrivent.",
		}},
	})
	w.record(now, err)
	return err
}

func (w *Watcher) record(now time.Time, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.LastAttempt = now
	if err != nil {
		w.status.Failed++
		w.status.LastError = err.Error()
		return
	}
	w.status.Sent++
	w.status.LastSuccess = now
	w.status.LastError = ""
}

func (w *Watcher) note(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.LastError = err.Error()
}
