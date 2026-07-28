package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"synsec/internal/auth"
	"synsec/internal/store"
)

const sessionCookie = "synsec_session"

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxSessionToken
	ctxScale
	ctxCanReadAudit
)

// requireLogin refuses anything without a live session, and checks the CSRF
// token on anything that is not a plain read.
func (s *Server) requireLogin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, user, session, ok := s.currentSession(r)
		if !ok {
			s.clearSessionCookie(w)
			// A cookie that no longer resolves is a session that lapsed, not
			// someone arriving fresh. Saying so is the difference between
			// "why am I on the login page" and "ah, I left it open too long".
			target := "/login"
			if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
				target += "?expiree=1"
			}
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !validCSRF(w, r, token) {
				s.render(w, r, "message.html", http.StatusForbidden, pageData{
					Title: "Action refusée",
					User:  &user,
					Error: "Ce formulaire a expiré. Recharge la page et recommence.",
				})
				return
			}
		}

		// Sliding expiry, capped at the absolute ceiling: every request pushes
		// the idle timeout back, so an interface in use never lapses under
		// someone's hands.
		expiry := auth.SessionExpiryWith(s.sessionIdle, session.CreatedAt, s.now())
		if err := s.vault.DB().TouchSession(r.Context(), session.ID, s.now(), expiry); err != nil {
			logError(r, err)
		}
		// The cookie is reissued, not only the row. Set once at sign-in, its
		// own Expires would run out while the server still considered the
		// session live, and the browser would drop it mid-use - which with a
		// short idle timeout means being signed out while typing.
		s.setSessionCookie(w, token, expiry)

		ctx := context.WithValue(r.Context(), ctxUser, user)
		ctx = context.WithValue(ctx, ctxSessionToken, token)
		// Resolved once here rather than in each handler: every page is drawn
		// at this size, and render picks it up from the context on its own.
		ctx = context.WithValue(ctx, ctxScale, s.loadScale(ctx, user))

		// The sidebar has to know whether to show the journal at all, so this
		// is resolved for every page rather than only for the journal itself.
		canAudit, err := s.vault.DB().CanReadAudit(ctx, user)
		if err != nil {
			logError(r, err)
		}
		ctx = context.WithValue(ctx, ctxCanReadAudit, canAudit)

		h(w, r.WithContext(ctx))
	}
}

// currentSession resolves the cookie on a request.
func (s *Server) currentSession(r *http.Request) (token string, user store.User, session store.Session, ok bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return "", store.User{}, store.Session{}, false
	}

	session, err = s.vault.DB().SessionByTokenHash(
		r.Context(), auth.HashSessionToken(cookie.Value), s.now())
	if err != nil {
		return "", store.User{}, store.Session{}, false
	}

	user, err = s.vault.DB().User(r.Context(), session.UserID)
	if err != nil {
		return "", store.User{}, store.Session{}, false
	}
	return cookie.Value, user, session, true
}

// userFrom reads the signed-in user placed in the context by requireLogin.
func userFrom(r *http.Request) store.User {
	u, _ := r.Context().Value(ctxUser).(store.User)
	return u
}

func csrfFrom(r *http.Request) string {
	token, _ := r.Context().Value(ctxSessionToken).(string)
	return csrfToken(token)
}

// csrfToken derives a form token from the session cookie.
//
// Deriving rather than storing keeps the database out of it entirely: the
// token is valid exactly as long as the session, cannot be reused across
// sessions, and needs no extra column and no cleanup.
func csrfToken(sessionToken string) string {
	mac := hmac.New(sha256.New, []byte(sessionToken))
	mac.Write([]byte("synsec-csrf-v1"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// maxRequestBytes caps any body the interface accepts.
//
// Ordinary forms are a few hundred bytes; the one exception is an imported
// secrets file. Applied here rather than in each handler, so a body cannot be
// read at all before the request has proved it belongs to a session.
const maxRequestBytes = 2 << 20

func validCSRF(w http.ResponseWriter, r *http.Request, sessionToken string) bool {
	// w is passed so that an oversized body closes the connection rather than
	// leaving the server trying to keep it alive.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)

	// A multipart body is not read by ParseForm, so the token would never be
	// found and every upload would look like a forged request. Parsing it here
	// also means the handler receives an already-decoded form.
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(multipartMemory); err != nil {
			return false
		}
	} else if err := r.ParseForm(); err != nil {
		return false
	}

	got := r.FormValue("csrf")
	if got == "" {
		return false
	}
	return hmac.Equal([]byte(got), []byte(csrfToken(sessionToken)))
}

// multipartMemory is how much of an upload is held in memory before the rest
// would spill to a temporary file.
//
// Deliberately at least as large as maxRequestBytes, so nothing ever spills:
// an uploaded secrets file is read, decrypted into the vault and forgotten,
// without a plaintext copy of every household password appearing in the
// operating system's temporary directory, however briefly.
const multipartMemory = maxRequestBytes

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.secureCookies,
		// Strict rather than Lax: nothing links into SYNSEC from elsewhere,
		// so there is no navigation to preserve, and Strict is the stronger
		// defence against a form posted from another site.
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

// Login throttling.
const (
	throttleAfter   = 5
	throttleBase    = time.Minute
	throttleCeiling = 15 * time.Minute
)

// throttle slows down repeated failed sign-ins.
//
// Argon2id already makes each attempt expensive, but a server sitting on a
// home network is reachable by every device on it, including one that has been
// compromised. The counter is in memory: a restart clears it, which is
// acceptable for the threat it addresses and avoids writing to disk on every
// wrong password.
type throttle struct {
	mu      sync.Mutex
	records map[string]*throttleRecord
}

type throttleRecord struct {
	failures int
	until    time.Time
}

func newThrottle() *throttle {
	return &throttle{records: make(map[string]*throttleRecord)}
}

// blocked reports whether a key must wait, and for how long.
func (t *throttle) blocked(key string, now time.Time) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	rec, ok := t.records[key]
	if !ok || rec.until.IsZero() || !rec.until.After(now) {
		return 0, false
	}
	return rec.until.Sub(now), true
}

// fail records a failed attempt and extends the lockout once past the
// threshold, doubling each time up to the ceiling.
func (t *throttle) fail(key string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	rec, ok := t.records[key]
	if !ok {
		rec = &throttleRecord{}
		t.records[key] = rec
	}
	rec.failures++

	if rec.failures < throttleAfter {
		return
	}
	wait := throttleBase << (rec.failures - throttleAfter)
	if wait > throttleCeiling || wait <= 0 {
		wait = throttleCeiling
	}
	rec.until = now.Add(wait)
}

// succeed forgets a key's history after a correct password.
func (t *throttle) succeed(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.records, key)
}
