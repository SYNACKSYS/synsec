package web

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"synsec/internal/store"
)

// Re-asking for the password before something irreversible.
//
// A session is a convenience, not a proof of presence: a browser left open on
// a kitchen tablet is a session, and so is a crawler that was handed an
// account. Reading through one is what it is for. Destroying a vault, deleting
// a secret, taking over somebody's account - those deserve the person, not the
// tab.
//
// One confirmation covers a few minutes rather than one action. Asking on
// every click trains people to type their password without reading, which is
// the habit that hands it to the next page that asks.

// confirmWindow is how long a confirmation lasts. Long enough to clean up
// several vaults in a row, short enough that a tab left open goes cold.
const confirmWindow = 5 * time.Minute

// sensitive reports whether an action asks for the password again.
//
// Decided here rather than in each handler, so an action added later is a line
// in this function instead of a check somebody forgets to copy.
func sensitive(path string) bool {
	// Two families ask again: what cannot be undone, and what hands access to
	// somebody or something else. Taking access away is not on the list -
	// revoking a token or removing a member fails safe, and asking there would
	// only teach people to type their password without reading the page.
	switch path {
	case "/comptes/supprimer", "/comptes/motdepasse":
		// Removing an account, or taking one over.
		return true
	case "/journal/acces":
		// Opening the journal, which spans every vault on the server.
		return true
	}

	if !strings.HasPrefix(path, "/coffres/") {
		return false
	}
	switch {
	case strings.HasSuffix(path, "/supprimer"):
		// A vault or a secret. Neither comes back without a backup.
		return true
	case strings.HasSuffix(path, "/membres"), strings.HasSuffix(path, "/partages"):
		// Handing a vault, or one secret, to another account.
		return true
	case strings.HasSuffix(path, "/appareils"), strings.HasSuffix(path, "/appareils/portee"):
		// Minting a token, or widening one. A token works from anywhere on the
		// network, without a password, until somebody revokes it - the same
		// reason the command line now asks for one before creating it.
		return true
	}
	return false
}

// confirmations remembers which sessions have proved themselves lately.
//
// In memory, like the sign-in throttle: a restart asks again, which costs one
// password and leaves nothing on disk.
type confirmations struct {
	mu    sync.Mutex
	until map[string]time.Time
}

func newConfirmations() *confirmations {
	return &confirmations{until: make(map[string]time.Time)}
}

func (c *confirmations) grant(session string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forgetExpired(now)
	c.until[session] = now.Add(confirmWindow)
}

func (c *confirmations) holds(session string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return now.Before(c.until[session])
}

// drop forgets a session's confirmation, so signing out or changing a password
// does not leave one standing.
func (c *confirmations) drop(session string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.until, session)
}

func (c *confirmations) forgetExpired(now time.Time) {
	for session, until := range c.until {
		if now.After(until) {
			delete(c.until, session)
		}
	}
}

// needsConfirmation reports whether this request must be held until the
// password has been given again.
func (s *Server) needsConfirmation(r *http.Request, sessionToken string) bool {
	if r.Method != http.MethodPost || !sensitive(r.URL.Path) {
		return false
	}
	return !s.confirmations.holds(sessionToken, s.now())
}

// returnTo is the page to come back to once the password is given.
//
// The referring page when the browser sent one and it belongs here, the home
// page otherwise. Never the action itself: a POST cannot be replayed by a
// redirect, so the person lands where they were and presses the button again.
func returnTo(r *http.Request) string {
	ref := r.Referer()
	if ref == "" {
		return "/"
	}
	if parsed, err := url.Parse(ref); err == nil {
		return safeReturn(parsed.RequestURI())
	}
	return "/"
}

// showConfirm asks for the password before an action that cannot be undone.
func (s *Server) showConfirm(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	s.render(w, r, "confirm.html", http.StatusOK, pageData{
		Title:  "Confirme ton mot de passe",
		User:   &user,
		CSRF:   csrfFrom(r),
		Sealed: s.vault.Sealed(),
		Back:   safeReturn(r.URL.Query().Get("retour")),
		Error:  r.URL.Query().Get("erreur"),
	})
}

// doConfirm checks the password and opens the window.
func (s *Server) doConfirm(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	back := safeReturn(r.PostFormValue("retour"))

	// The same throttle as the sign-in form, and for a sharper reason: this
	// page is reachable precisely by whoever already holds a session. Left
	// unthrottled it would be a password oracle for anyone who found an open
	// tab, at whatever rate Argon2id allows.
	key := s.clientIP(r)
	if wait, blocked := s.throttle.blocked(key, s.now()); blocked {
		s.redirectWithError(w, r, "/confirmer?retour="+urlEncode(back),
			"Trop de tentatives. Réessaie dans "+humanDuration(wait)+".")
		return
	}

	_, ok, busy := s.verify(r, user.Username, r.PostFormValue("password"))
	if busy {
		s.redirectWithError(w, r, "/confirmer?retour="+urlEncode(back),
			"Le serveur est momentanément surchargé. Réessaie dans quelques secondes.")
		return
	}
	if !ok {
		s.throttle.fail(key, s.now())
		s.audit(r, store.AuditEntry{
			ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
			Action: "auth.failed", Detail: "confirmation avant une action irréversible",
		})
		s.redirectWithError(w, r, "/confirmer?retour="+urlEncode(back), "Mot de passe incorrect.")
		return
	}
	s.throttle.succeed(key)

	token, _ := r.Context().Value(ctxSessionToken).(string)
	s.confirmations.grant(token, s.now())
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// safeReturn keeps the return address on this site.
//
// It comes from the query string, so it is somewhere a visitor could have put
// anything. A path, never an authority: "//ailleurs.example" is a URL, not a
// page of this server.
func safeReturn(path string) string {
	if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return "/"
	}
	if _, err := url.Parse(path); err != nil {
		return "/"
	}
	return path
}
