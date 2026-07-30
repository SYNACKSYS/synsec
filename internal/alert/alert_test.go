package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"synsec/internal/store"
)

// receiver stands in for whatever is listening: Home Assistant, ntfy, a
// script. It keeps what it was sent so the test can read it back.
type receiver struct {
	mu       sync.Mutex
	messages []message
	bodies   []string
	headers  []http.Header
	status   int
}

func (r *receiver) serve() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)

		r.mu.Lock()
		defer r.mu.Unlock()
		var m message
		json.Unmarshal(body, &m) //nolint:errcheck // a malformed body is what the test is looking at
		r.messages = append(r.messages, m)
		r.bodies = append(r.bodies, string(body))
		r.headers = append(r.headers, req.Header.Clone())
		if r.status != 0 {
			w.WriteHeader(r.status)
		}
	}))
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.messages)
}

func (r *receiver) events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Event
	for _, m := range r.messages {
		out = append(out, m.Events...)
	}
	return out
}

// harness is a database, a watcher, and a clock the test moves by hand.
type harness struct {
	db      *store.DB
	watcher *Watcher
	now     time.Time
	cfg     Config
	rx      *receiver
}

func newHarness(t *testing.T, level Severity) *harness {
	t.Helper()

	db, err := store.Open(filepath.Join(t.TempDir(), "synsec.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	rx := &receiver{}
	srv := rx.serve()
	t.Cleanup(srv.Close)

	h := &harness{
		db:  db,
		now: time.Date(2026, 7, 30, 3, 0, 0, 0, time.UTC),
		rx:  rx,
	}
	h.cfg = Config{
		Enabled: true,
		Level:   level,
		Webhook: Webhook{URL: srv.URL, Secret: "clef-de-test", Server: "synsec-test",
			Client: srv.Client(), Now: func() time.Time { return h.now }},
	}
	h.watcher = NewWatcher(db, func(context.Context) (Config, error) { return h.cfg, nil })
	h.watcher.now = func() time.Time { return h.now }
	return h
}

// write adds a journal line, the way the rest of SYNSEC would.
func (h *harness) write(t *testing.T, e store.AuditEntry) {
	t.Helper()
	if e.At.IsZero() {
		e.At = h.now
	}
	if err := h.db.AppendAudit(context.Background(), e); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
}

// tick runs one pass and lets time move on far enough to flush.
func (h *harness) tick(t *testing.T) {
	t.Helper()
	if err := h.watcher.pass(context.Background()); err != nil {
		t.Fatalf("pass: %v", err)
	}
	h.now = h.now.Add(flushAfter + time.Second)
	if err := h.watcher.pass(context.Background()); err != nil {
		t.Fatalf("flush pass: %v", err)
	}
}

func denied(detail string) store.AuditEntry {
	return store.AuditEntry{
		ActorKind: store.ActorToken, ActorID: "tok", ActorLabel: "domotique",
		Action: "access.denied", Target: "mot_de_passe_mqtt", IP: "203.0.113.7",
		Detail: detail,
	}
}

func TestARefusedAddressIsSentStraightAway(t *testing.T) {
	h := newHarness(t, SeverityCritical)
	h.write(t, denied("adresse non autorisée pour ce secret"))
	h.tick(t)

	events := h.rx.events()
	if len(events) != 1 {
		t.Fatalf("%d événement(s) reçu(s), attendu 1", len(events))
	}
	e := events[0]
	if e.Kind != KindAccessDeniedAddress {
		t.Errorf("kind = %q", e.Kind)
	}
	if e.Severity != "critique" {
		t.Errorf("severity = %q, un refus par filtrage doit être critique", e.Severity)
	}
	if e.Actor != "domotique" || e.Target != "mot_de_passe_mqtt" || e.IP != "203.0.113.7" {
		t.Errorf("l'événement ne dit pas de quoi il parle : %+v", e)
	}
}

// The one that decides whether this is usable: a scan makes thousands of
// refusals, and a phone that buzzes thousands of times gets silenced for good.
func TestABurstBecomesOneMessageWithACount(t *testing.T) {
	h := newHarness(t, SeverityCritical)
	for i := 0; i < 2000; i++ {
		h.write(t, denied("adresse non autorisée pour ce secret"))
	}
	h.tick(t)

	if got := h.rx.count(); got != 1 {
		t.Fatalf("%d messages envoyés pour une rafale, attendu 1", got)
	}
	events := h.rx.events()
	if len(events) != 1 {
		t.Fatalf("%d lignes dans le message, attendu 1", len(events))
	}
	if events[0].Count != 2000 {
		t.Errorf("le compte annoncé est %d, attendu 2000", events[0].Count)
	}
}

// And the burst does not keep sending every ten seconds either.
func TestTheSameKindStaysQuietForAWhile(t *testing.T) {
	h := newHarness(t, SeverityCritical)
	h.write(t, denied("adresse non autorisée"))
	h.tick(t)

	h.write(t, denied("adresse non autorisée"))
	h.tick(t)

	if got := h.rx.count(); got != 1 {
		t.Fatalf("%d messages, le deuxième aurait dû attendre la fin du silence", got)
	}

	// Once the mute expires it goes out, carrying what accumulated.
	h.now = h.now.Add(muteFor)
	if err := h.watcher.pass(context.Background()); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if got := h.rx.count(); got != 2 {
		t.Fatalf("%d messages après la fin du silence, attendu 2", got)
	}
}

func TestTheLevelDecidesWhatGoesOut(t *testing.T) {
	h := newHarness(t, SeverityCritical)
	h.write(t, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: "u", ActorLabel: "cyril",
		Action: "vault.grant", Target: "Maison",
	})
	h.tick(t)
	if got := h.rx.count(); got != 0 {
		t.Fatalf("un avertissement est parti alors que le niveau est « critique »")
	}

	h.cfg.Level = SeverityWarning
	h.write(t, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: "u", ActorLabel: "cyril",
		Action: "vault.grant", Target: "Maison",
	})
	h.tick(t)
	if got := h.rx.count(); got != 1 {
		t.Fatalf("%d messages au niveau « avertissement », attendu 1", got)
	}
}

// A brand new device has to speak from somewhere the first time. Announcing
// that would mean an alert for every token ever created, and the owner would
// learn on day one that these messages mean nothing.
func TestTheFirstAddressIsLearnedQuietlyAndTheSecondIsNot(t *testing.T) {
	h := newHarness(t, SeverityInfo)

	h.write(t, store.AuditEntry{
		ActorKind: store.ActorToken, ActorID: "tok", ActorLabel: "domotique",
		Action: "secret.read", Target: "mqtt", IP: "192.168.1.30",
	})
	h.tick(t)
	if got := h.rx.count(); got != 0 {
		t.Fatalf("la première adresse d'un appareil a déclenché un message")
	}

	h.write(t, store.AuditEntry{
		ActorKind: store.ActorToken, ActorID: "tok", ActorLabel: "domotique",
		Action: "secret.read", Target: "mqtt", IP: "203.0.113.7",
	})
	h.tick(t)

	events := h.rx.events()
	if len(events) != 1 || events[0].Kind != KindNewAddress {
		t.Fatalf("l'adresse jamais vue n'a pas été signalée : %+v", events)
	}
	if events[0].IP != "203.0.113.7" {
		t.Errorf("le message ne dit pas quelle adresse : %+v", events[0])
	}
}

// Reads are not sent. A household does thousands a week and a notification
// that frequent is one nobody reads.
func TestOrdinaryReadsAreNotAnnounced(t *testing.T) {
	h := newHarness(t, SeverityInfo)
	h.write(t, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: "u", ActorLabel: "cyril",
		Action: "secret.read", Target: "mqtt", IP: "192.168.1.20",
	})
	h.tick(t)
	// The first address is learned silently, so nothing at all should go out.
	if got := h.rx.count(); got != 0 {
		t.Fatalf("une lecture ordinaire a déclenché %d message(s)", got)
	}
}

// Turning alerts on must not replay the history of the installation.
func TestSwitchingItOnDoesNotAnnounceThePast(t *testing.T) {
	h := newHarness(t, SeverityCritical)
	for i := 0; i < 10; i++ {
		h.write(t, denied("adresse non autorisée"))
	}
	if err := h.watcher.start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	h.tick(t)
	if got := h.rx.count(); got != 0 {
		t.Fatalf("%d message(s) pour des lignes antérieures au démarrage", got)
	}
}

func TestTheSignatureCoversTheBodyAndTheTimestamp(t *testing.T) {
	h := newHarness(t, SeverityCritical)
	h.write(t, denied("adresse non autorisée"))
	h.tick(t)

	h.rx.mu.Lock()
	defer h.rx.mu.Unlock()
	if len(h.rx.headers) == 0 {
		t.Fatal("rien n'a été reçu")
	}
	head, body := h.rx.headers[0], h.rx.bodies[0]

	stamp := head.Get(timestampHeader)
	if stamp == "" {
		t.Fatal("pas d'horodatage")
	}
	want := Sign("clef-de-test", stamp, []byte(body))
	if got := head.Get(signatureHeader); got != want {
		t.Fatalf("signature = %q, attendu %q", got, want)
	}
	// The same body under a different timestamp must not verify, or a message
	// captured once could be replayed as fresh news.
	if Sign("clef-de-test", "1", []byte(body)) == want {
		t.Error("l'horodatage n'entre pas dans la signature")
	}
}

// Nothing that carries a value ever reaches a webhook. The journal holds none
// either, so this is belt and braces - which is the point: it stays true only
// as long as somebody checks.
func TestNoSecretValueEverLeaves(t *testing.T) {
	h := newHarness(t, SeverityInfo)
	h.write(t, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: "u", ActorLabel: "cyril",
		Action: "secret.delete", Target: "mot_de_passe_mqtt", IP: "192.168.1.20",
		Detail: "supprimé",
	})
	h.tick(t)

	h.rx.mu.Lock()
	defer h.rx.mu.Unlock()
	for _, body := range h.rx.bodies {
		for _, forbidden := range []string{"value", "valeur", "password="} {
			if strings.Contains(strings.ToLower(body), forbidden) {
				t.Errorf("le message contient %q : %s", forbidden, body)
			}
		}
	}
}

func TestARefusingReceiverIsNotHammered(t *testing.T) {
	h := newHarness(t, SeverityCritical)
	h.rx.status = http.StatusBadRequest

	h.write(t, denied("adresse non autorisée"))
	if err := h.watcher.pass(context.Background()); err != nil {
		t.Fatalf("pass: %v", err)
	}
	h.now = h.now.Add(flushAfter + time.Second)
	if err := h.watcher.pass(context.Background()); err == nil {
		t.Fatal("un refus du destinataire est passé pour un succès")
	}

	if got := h.rx.count(); got != 1 {
		t.Fatalf("%d tentatives pour une réponse 400, attendu 1 : un « non » se réessaie en vain", got)
	}
	if st := h.watcher.Status(); st.LastError == "" || st.Failed != 1 {
		t.Errorf("l'état ne rapporte pas l'échec : %+v", st)
	}
}

func TestAnAddressThatCannotBePostedToIsRefusedEarly(t *testing.T) {
	for _, bad := range []string{"", "ftp://ailleurs", "pas une adresse", "https://"} {
		if err := ValidateURL(bad); err == nil {
			t.Errorf("ValidateURL(%q) accepte", bad)
		}
	}
	for _, good := range []string{"http://192.168.1.5:8123/api/webhook/x", "https://ntfy.sh/mon-sujet"} {
		if err := ValidateURL(good); err != nil {
			t.Errorf("ValidateURL(%q) refuse : %v", good, err)
		}
	}
}
