// Package web serves the browser interface.
//
// Server-rendered Go templates with a little htmx, rather than a single-page
// application. There is no build step, no bundle to ship and nothing to keep
// in sync - which matters for something meant to be installed by copying one
// executable, and keeps the whole interface inside the same binary.
package web

import (
	"bytes"
	"crypto/rand"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"time"

	"synsec/internal/auth"
	"synsec/internal/clientip"
	"synsec/internal/store"
	"synsec/internal/vault"
)

//go:embed templates/*.html static/*
var assets embed.FS

// pageNames are the templates rendered inside the shared layout.
var pageNames = []string{
	"login.html",
	"twofactor.html",
	"source.html",
	"home.html",
	"message.html",
	"vault.html",
	"vault_new.html",
	"import.html",
	"import_done.html",
	"tokens.html",
	"token_scope.html",
	"secret.html",
	"members.html",
	"shares.html",
	"accounts.html",
	"password.html",
	"own_password.html",
	"twofactor_settings.html",
	"twofactor_codes.html",
	"securitykeys.html",
	"audit.html",
	"audit_access.html",
	"settings.html",
}

// Server renders the browser interface.
type Server struct {
	vault *vault.Manager
	pages map[string]*template.Template
	now   func() time.Time

	// secureCookies marks the session cookie Secure.
	//
	// Always on in production: SYNSEC has no plain-HTTP mode. The switch
	// exists only for the tests, which run against an httptest server that
	// speaks HTTP and would otherwise see every cookie discarded.
	secureCookies bool

	// sessionIdle is how long a browser may sit untouched. Held here rather
	// than read from the package constant so the operator can set it.
	sessionIdle time.Duration

	// clients decides which address a request came from, and allow restricts
	// which of them may reach the interface at all.
	clients *clientip.Resolver
	allow   []string

	// requireFactor makes a second factor compulsory for every account. An
	// account that has none can reach the enrolment pages and nothing else.
	requireFactor bool

	// pendingKey signs a sign-in that has passed the password and still owes a
	// code. Made at start-up and never stored: a restart cancels the sign-ins
	// in progress, which costs one password re-entry and leaves no key on disk.
	pendingKey []byte

	// challenges holds the security key ceremonies in flight, and freshCodes
	// the recovery codes waiting to be shown once. Both are in memory: a
	// restart cancels a ceremony, which costs one retry.
	challenges *challengeStore
	freshCodes *codeStash

	throttle *throttle
}

// TrustProxies believes X-Forwarded-For from the named addresses only.
func TrustProxies(r *clientip.Resolver) Option {
	return func(s *Server) { s.clients = r }
}

// RestrictTo refuses the interface to any address outside the list. Empty
// means anywhere.
//
// The API has per-token allowlists; the browser had nothing. On a server
// anyone can reach, this is the cheapest thing that turns a password guess
// into a packet that never arrives.
func RestrictTo(entries []string) Option {
	return func(s *Server) { s.allow = entries }
}

// RequireSecondFactor makes a second factor compulsory for every account.
//
// The operator's decision, not each person's: an account that carries only a
// password is the one that falls to a credential leaked somewhere else, and on
// a server anyone can reach that is the whole attack. Signing in still works -
// there would be no way to enrol otherwise - but the session reaches the
// enrolment pages and nothing else until a factor exists.
func RequireSecondFactor(on bool) Option {
	return func(s *Server) { s.requireFactor = on }
}

// WithSessionIdle sets how long a browser may sit untouched before being
// signed out. Out-of-range values fall back to the default.
func WithSessionIdle(d time.Duration) Option {
	return func(s *Server) { s.sessionIdle = auth.ClampSessionIdle(d) }
}

// Option configures a Server.
type Option func(*Server)

// InsecureCookies allows the session cookie over plain HTTP.
//
// For tests only. Nothing in the server ever calls it, because the server
// never listens without TLS.
func InsecureCookies() Option {
	return func(s *Server) { s.secureCookies = false }
}

func withClock(now func() time.Time) Option {
	return func(s *Server) { s.now = now }
}

// New parses the templates and returns a ready server.
func New(v *vault.Manager, opts ...Option) (*Server, error) {
	s := &Server{
		vault:         v,
		now:           time.Now,
		secureCookies: true,
		sessionIdle:   auth.SessionIdle,
		throttle:      newThrottle(),
		challenges:    newChallengeStore(),
		freshCodes:    newCodeStash(),
	}
	s.clients, _ = clientip.New(nil)

	s.pendingKey = make([]byte, 32)
	if _, err := rand.Read(s.pendingKey); err != nil {
		return nil, fmt.Errorf("web: generating the sign-in key: %w", err)
	}
	for _, opt := range opts {
		opt(s)
	}

	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	s.pages = pages
	return s, nil
}

// parsePages builds one template set per page.
//
// Go templates share a single namespace, so a layout plus every page parsed
// together would leave the pages fighting over the "content" block. One set
// per page keeps each definition unambiguous.
func parsePages() (map[string]*template.Template, error) {
	out := make(map[string]*template.Template, len(pageNames))
	for _, name := range pageNames {
		t, err := template.New("layout.html").
			Funcs(templateFuncs()).
			ParseFS(assets, "templates/layout.html", "templates/"+name)
		if err != nil {
			return nil, fmt.Errorf("web: parsing %s: %w", name, err)
		}
		out[name] = t
	}
	return out, nil
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"date": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Format("02/01/2006 à 15:04")
		},
		// The same helper the handlers use, so a count worded in a page and a
		// count worded in the audit log cannot disagree.
		"plural": plural,
	}
}

// Handler returns the routed interface.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /static/", s.staticHandler())

	// Unauthenticated, like the sign-in page: the licence notice is owed to
	// anyone the server talks to, not only to those with an account.
	mux.HandleFunc("GET /source", s.showSource)

	mux.HandleFunc("GET /login", s.showLogin)
	mux.HandleFunc("POST /login", s.doLogin)
	mux.HandleFunc("POST /login/code", s.finishSecondFactor)
	// The security key half of the same step. Scripted rather than a form: the
	// browser has to talk to the key between the two requests.
	mux.HandleFunc("POST /login/cle/defi", s.startKeyAssertion)
	mux.HandleFunc("POST /login/cle", s.finishKeyAssertion)
	mux.HandleFunc("POST /logout", s.requireLogin(s.doLogout))

	mux.HandleFunc("GET /{$}", s.requireLogin(s.showHome))
	mux.HandleFunc("POST /coffres", s.requireLogin(s.createVault))
	// A literal segment wins over a wildcard in the standard mux, so this
	// stays reachable even though it looks like a vault identifier.
	mux.HandleFunc("GET /coffres/nouveau", s.requireLogin(s.showNewVault))
	mux.HandleFunc("GET /coffres/{id}", s.requireLogin(s.showVault))
	mux.HandleFunc("POST /coffres/{id}/supprimer", s.requireLogin(s.deleteVault))
	mux.HandleFunc("GET /coffres/{id}/secret", s.requireLogin(s.showSecret))
	mux.HandleFunc("POST /coffres/{id}/secret", s.requireLogin(s.saveSecret))
	mux.HandleFunc("POST /coffres/{id}/secret/supprimer", s.requireLogin(s.deleteSecret))
	mux.HandleFunc("POST /coffres/{id}/secret/revenir", s.requireLogin(s.revertSecret))

	mux.HandleFunc("GET /coffres/{id}/import", s.requireLogin(s.showImport))
	mux.HandleFunc("POST /coffres/{id}/import", s.requireLogin(s.runImport))

	mux.HandleFunc("GET /coffres/{id}/appareils", s.requireLogin(s.showTokens))
	mux.HandleFunc("POST /coffres/{id}/appareils", s.requireLogin(s.createToken))
	mux.HandleFunc("POST /coffres/{id}/appareils/revoquer", s.requireLogin(s.revokeToken))
	mux.HandleFunc("GET /coffres/{id}/appareils/portee", s.requireLogin(s.showTokenScope))
	mux.HandleFunc("POST /coffres/{id}/appareils/portee", s.requireLogin(s.saveTokenScope))

	mux.HandleFunc("POST /coffres/{id}/secret/adresses", s.requireLogin(s.addNetwork))
	mux.HandleFunc("POST /coffres/{id}/secret/adresses/retirer", s.requireLogin(s.removeNetwork))

	mux.HandleFunc("GET /coffres/{id}/membres", s.requireLogin(s.showMembers))
	mux.HandleFunc("POST /coffres/{id}/membres", s.requireLogin(s.addMember))
	mux.HandleFunc("POST /coffres/{id}/membres/retirer", s.requireLogin(s.removeMember))

	mux.HandleFunc("GET /parametres", s.requireLogin(s.showSettings))
	mux.HandleFunc("POST /parametres/apparence", s.requireLogin(s.saveAppearance))
	mux.HandleFunc("GET /parametres/motdepasse", s.requireLogin(s.showOwnPassword))
	mux.HandleFunc("POST /parametres/motdepasse", s.requireLogin(s.changeOwnPassword))
	mux.HandleFunc("GET /parametres/verification", s.requireLogin(s.showTwoFactorSettings))
	mux.HandleFunc("POST /parametres/verification", s.requireLogin(s.enableTwoFactor))
	mux.HandleFunc("POST /parametres/verification/desactiver", s.requireLogin(s.disableTwoFactor))
	mux.HandleFunc("GET /parametres/cles", s.requireLogin(s.showSecurityKeys))
	mux.HandleFunc("POST /parametres/cles/defi", s.requireLogin(s.startKeyRegistration))
	mux.HandleFunc("POST /parametres/cles", s.requireLogin(s.finishKeyRegistration))
	mux.HandleFunc("POST /parametres/cles/retirer", s.requireLogin(s.removeSecurityKey))
	mux.HandleFunc("GET /parametres/secours", s.requireLogin(s.showFreshRecoveryCodes))

	mux.HandleFunc("GET /comptes", s.requireAdmin(s.showAccounts))
	mux.HandleFunc("POST /comptes", s.requireAdmin(s.createAccount))
	mux.HandleFunc("GET /comptes/motdepasse", s.requireAdmin(s.showPasswordForm))
	mux.HandleFunc("POST /comptes/motdepasse", s.requireAdmin(s.resetPassword))
	mux.HandleFunc("POST /comptes/supprimer", s.requireAdmin(s.deleteAccount))

	mux.HandleFunc("GET /journal", s.requireAuditReader(s.showAudit))
	// Handing the journal to someone else is the root account's alone, so it
	// is gated on that rather than on being able to read it.
	mux.HandleFunc("GET /journal/acces", s.requireRoot(s.showAuditAccess))
	mux.HandleFunc("POST /journal/acces", s.requireRoot(s.grantAuditAccess))
	mux.HandleFunc("POST /journal/acces/retirer", s.requireRoot(s.revokeAuditAccess))

	mux.HandleFunc("GET /coffres/{id}/partages", s.requireLogin(s.showShares))
	mux.HandleFunc("POST /coffres/{id}/partages", s.requireLogin(s.addShare))
	mux.HandleFunc("POST /coffres/{id}/partages/retirer", s.requireLogin(s.removeShare))

	return s.restrict(securityHeaders(mux))
}

func (s *Server) staticHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The assets are embedded and change only when the binary does, so
		// they can be cached hard.
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.FileServerFS(assets).ServeHTTP(w, r)
	})
}

// render writes a page, or an error page if the template fails.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, status int, data any) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "page inconnue", http.StatusInternalServerError)
		return
	}

	// Filled here so no handler has to remember it. Only a size that differs
	// from the default is carried: the sign-in page has no account to read a
	// preference from, and someone who never chose anything gets the plain
	// stylesheet rather than a class that resolves to the same thing.
	if d, ok := data.(pageData); ok && d.User != nil {
		if scale := scaleFrom(r); d.Scale == 0 && scale != defaultScale {
			d.Scale = scale
		}
		d.CanReadAudit = canReadAuditFrom(r)
		d.RequireFactor = s.requireFactor
		d.MustEnrol = mustEnrolFrom(r)
		data = d
	}

	// Rendered to memory first: a template that fails halfway would otherwise
	// leave a half-written page with a 200 already on the wire.
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout.html", data); err != nil {
		logError(r, fmt.Errorf("rendering %s: %w", page, err))
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

// restrict refuses the whole interface to addresses outside the allowlist.
//
// Before routing and before any session lookup: an address that has no
// business here should not reach the sign-in form, let alone spend a password
// derivation.
func (s *Server) restrict(next http.Handler) http.Handler {
	if len(s.allow) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !store.AddressAllowed(s.allow, s.clients.From(r)) {
			http.Error(w, "interdit", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders sets what matters for a page that displays secrets.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// SYNSEC has no plain-HTTP mode, but a browser given "serveur:8787"
		// presumes http and sends that first request in clear, where anyone on
		// the network can answer in its place. This tells the browser never to
		// try again, so only the very first visit is exposed.
		h.Set("Strict-Transport-Security", "max-age=31536000")
		// Everything is served from this origin; nothing is fetched elsewhere.
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self'; "+
				"script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

// staticFS is exposed for tests that check the assets are actually embedded.
func staticFS() (fs.FS, error) { return fs.Sub(assets, "static") }

// logError records something the visitor is not shown.
//
// Interface errors can name vaults and paths, so the page says only that
// something went wrong and the detail goes to the operator's log.
func logError(r *http.Request, err error) {
	log.Printf("web: %s %s: %v", r.Method, r.URL.Path, err)
}
