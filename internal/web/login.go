package web

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"synsec/internal/auth"
	"synsec/internal/crypto"
	"synsec/internal/store"
)

// pageData is what every template receives.
type pageData struct {
	Title string
	// Nav marks the sidebar entry to highlight.
	Nav    string
	User   *store.User
	CSRF   string
	Error  string
	Notice string
	Sealed bool

	Vaults []vaultRow
	// SharedVaults are those someone else opened, kept apart from the ones
	// this person manages.
	SharedVaults []vaultRow
	Vault        *vaultRow
	Secrets      []secretRow
	Secret       *secretRow
	Value        string

	// Shared holds secrets handed to this person individually, outside any
	// vault they belong to.
	Shared []sharedRow

	// Members is who has access, on a vault page or a secret's share page.
	// Candidates is who could still be given some.
	Members    []memberRow
	Candidates []userRow

	// Tokens are the devices connected to a vault; NewToken carries a freshly
	// minted one, shown exactly once and never stored in the clear.
	Tokens   []tokenRow
	NewToken string
	// Token is the single device a page acts on, when setting its scope.
	Token *tokenRow
	// Networks are the addresses a secret is pinned to, and Host is where the
	// browser reached this server - used to build a ready-to-paste command.
	Networks []networkRow
	Host     string

	// Versions is a secret's history, metadata only.
	Versions []versionRow

	// Imported is the report of an import: one line per entry read, with what
	// became of it. Values are deliberately absent.
	Imported []importRow
	Written  int
	Skipped  int
	Filename string

	// Accounts is the server's user list, on the administration page;
	// Account is the single one a form acts on.
	Accounts []accountRow
	Account  *accountRow

	// Scale is the display size this account chose, as a percentage; Scales
	// are the choices offered on the settings page.
	Scale  int
	Scales []scaleRow

	// SessionIdle is the server's inactivity timeout, in words. Shown rather
	// than offered: it is the operator's setting, not a preference.
	SessionIdle string

	// SourceURL and Version answer the licence notice: which build this is,
	// and where its source can be fetched.
	SourceURL string
	Version   string

	// Audit is the log, with the filters offered above it. Truncated says the
	// limit was reached, so the page can admit it is not showing everything.
	Audit        []auditRow
	AuditActions []auditChoice
	AuditPeriods []auditChoice
	Search       string
	Truncated    bool

	// CanReadAudit decides whether the sidebar mentions the journal at all.
	CanReadAudit bool

	// Role is what the visitor may do here; CanWrite and CanManage save the
	// templates from reimplementing the comparison.
	Role      store.Role
	CanWrite  bool
	CanManage bool
	// CanDelete is stricter than CanManage: destroying a vault is the owner's
	// alone.
	CanDelete bool

	// CanSeeVault reports whether the visitor may open the vault a secret
	// lives in. Someone handed a single secret may not, so the page must not
	// offer them a way back into it.
	CanSeeVault bool

	// Back is where "cancel" and "return" lead: the vault when it is
	// reachable, the home page otherwise.
	Back string
}

type vaultRow struct {
	ID          string
	Name        string
	Description string
	Secrets     int
	CreatedAt   time.Time
	Role        store.Role
	OwnerName   string
}

type secretRow struct {
	Name      string
	Label     string
	Version   int64
	UpdatedAt time.Time
	// InScope marks the secrets a token reaches, on the page that sets it.
	InScope bool
}

// sharedRow is a secret reachable only through an individual share, so it
// carries the name of the vault it lives in - the reader has never seen it.
type sharedRow struct {
	VaultID   string
	VaultName string
	Name      string
	Label     string
	Role      store.Role
	UpdatedAt time.Time
}

// memberRow is one grant, on a vault or on a single secret.
type memberRow struct {
	UserID      string
	Username    string
	DisplayName string
	Role        store.Role
	GrantedAt   time.Time
	GrantedBy   string
}

// userRow is an account that could be granted access.
type userRow struct {
	ID          string
	Username    string
	DisplayName string
}

// accountRow is one account on the administration page. IsSelf lets the
// template hide the actions nobody should aim at themselves.
type accountRow struct {
	ID          string
	Username    string
	DisplayName string
	IsAdmin     bool
	IsRoot      bool
	CreatedAt   time.Time
	LastLoginAt time.Time
	IsSelf      bool
}

// urlEncode escapes a message for the query string.
func urlEncode(s string) string { return url.QueryEscape(s) }

func (s *Server) showLogin(w http.ResponseWriter, r *http.Request) {
	if _, _, _, ok := s.currentSession(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := pageData{Title: "Connexion"}
	if r.URL.Query().Get("expiree") != "" {
		data.Notice = "Ta session a expiré après " + humanDuration(s.sessionIdle) +
			" sans activité. Reconnecte-toi."
	}
	s.render(w, r, "login.html", http.StatusOK, data)
}

func (s *Server) doLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.render(w, r, "login.html", http.StatusBadRequest, pageData{
			Title: "Connexion", Error: "Formulaire illisible.",
		})
		return
	}

	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	now := s.now()

	// Throttling is keyed on the address rather than the username, so someone
	// working through a list of names cannot get a fresh budget for each.
	key := clientIP(r)
	if wait, blocked := s.throttle.blocked(key, now); blocked {
		s.audit(r, store.AuditEntry{
			ActorKind: store.ActorUser, ActorLabel: username,
			Action: "auth.throttled", Detail: "trop de tentatives",
		})
		s.render(w, r, "login.html", http.StatusTooManyRequests, pageData{
			Title: "Connexion",
			Error: "Trop de tentatives. Réessaie dans " + humanDuration(wait) + ".",
		})
		return
	}

	user, ok := s.verify(r, username, password)
	if !ok {
		s.throttle.fail(key, now)
		s.audit(r, store.AuditEntry{
			ActorKind: store.ActorUser, ActorLabel: username,
			Action: "auth.failed", Detail: "identifiants incorrects",
		})
		// One message for both causes: naming which half was wrong would let
		// anyone find out which accounts exist.
		s.render(w, r, "login.html", http.StatusUnauthorized, pageData{
			Title: "Connexion", Error: "Nom d'utilisateur ou mot de passe incorrect.",
		})
		return
	}
	s.throttle.succeed(key)

	token, hash, err := auth.NewSessionToken()
	if err != nil {
		logError(r, err)
		s.render(w, r, "login.html", http.StatusInternalServerError, pageData{
			Title: "Connexion", Error: "Erreur interne.",
		})
		return
	}

	expiry := auth.SessionExpiryWith(s.sessionIdle, now, now)
	session := store.Session{
		UserID:    user.ID,
		ExpiresAt: expiry,
		UserAgent: truncate(r.UserAgent(), 200),
		IP:        clientIP(r),
	}
	if err := s.vault.DB().CreateSession(r.Context(), &session, hash); err != nil {
		logError(r, err)
		s.render(w, r, "login.html", http.StatusInternalServerError, pageData{
			Title: "Connexion", Error: "Erreur interne.",
		})
		return
	}

	if err := s.vault.DB().TouchUserLogin(r.Context(), user.ID, now); err != nil {
		logError(r, err)
	}
	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "auth.signin",
	})

	s.setSessionCookie(w, token, expiry)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// verify checks a username and password.
//
// A missing account still costs a password hash, so the time taken cannot be
// used to tell an unknown name from a wrong password.
func (s *Server) verify(r *http.Request, username, password string) (store.User, bool) {
	user, err := s.vault.DB().UserByUsername(r.Context(), username)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			logError(r, err)
		}
		auth.VerifyPassword(decoyCredentials(), password)
		return store.User{}, false
	}

	cred, err := s.vault.DB().UserCredentials(r.Context(), user.ID)
	if err != nil {
		logError(r, err)
		return store.User{}, false
	}
	if !auth.VerifyPassword(cred, password) {
		return store.User{}, false
	}
	return user, true
}

// decoyCredentials is a well-formed verifier that nothing matches, used to
// spend the same time on an unknown account as on a real one.
func decoyCredentials() store.Credentials {
	return store.Credentials{
		Hash:   make([]byte, 32),
		Salt:   make([]byte, 16),
		Params: crypto.DefaultArgon2,
	}
}

func (s *Server) doLogout(w http.ResponseWriter, r *http.Request) {
	if _, _, session, ok := s.currentSession(r); ok {
		if err := s.vault.DB().DeleteSession(r.Context(), session.ID); err != nil {
			logError(r, err)
		}
		user := userFrom(r)
		s.audit(r, store.AuditEntry{
			ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
			Action: "auth.signout",
		})
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// audit appends an entry, filling in the address and time.
func (s *Server) audit(r *http.Request, e store.AuditEntry) {
	e.At = s.now()
	e.IP = clientIP(r)
	if err := s.vault.DB().AppendAudit(r.Context(), e); err != nil {
		logError(r, err)
	}
}

// clientIP uses the connection address only.
//
// The browser interface is reached directly on the home network, so there is
// no proxy header worth trusting - and trusting one would let a caller forge
// the address recorded in the audit log.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// humanDuration writes a delay the way someone would say it out loud, in the
// largest unit that still divides evenly.
func humanDuration(d time.Duration) string {
	minutes := int((d + time.Minute - 1) / time.Minute) // round up
	switch {
	case minutes <= 0:
		return "moins d'une minute"
	case minutes == 1:
		return "une minute"
	case minutes%(24*60) == 0:
		days := minutes / (24 * 60)
		if days == 1 {
			return "un jour"
		}
		return fmt.Sprintf("%d jours", days)
	case minutes%60 == 0:
		hours := minutes / 60
		if hours == 1 {
			return "une heure"
		}
		return fmt.Sprintf("%d heures", hours)
	default:
		return fmt.Sprintf("%d minutes", minutes)
	}
}

// Display is what a listing shows: the label its owner wrote, or the slug when
// the entry was created by a device that had no opinion on the matter.
func (r secretRow) Display() string {
	if r.Label != "" {
		return r.Label
	}
	return r.Name
}

// Display does the same for a secret reached through an individual share.
func (r sharedRow) Display() string {
	if r.Label != "" {
		return r.Label
	}
	return r.Name
}

// tokenRow is one device connected to a vault.
type tokenRow struct {
	ID       string
	Name     string
	CanWrite bool
	// Secrets is what the token reaches; empty means the whole vault.
	Secrets    []string
	State      string
	Live       bool
	Addresses  string
	ExpiresAt  time.Time
	LastUsedAt time.Time
}

// versionRow is one entry in a secret's history. It carries no value: listing
// the past must not decrypt it, or opening the page would quietly read every
// version a secret ever had.
type versionRow struct {
	Version   int64
	CreatedAt time.Time
	CreatedBy string
	Current   bool
}

// importRow is one line of an import report: the key as the file wrote it, the
// identifier derived from it, and what happened.
type importRow struct {
	Key    string
	Name   string
	Reason string
	Skip   bool
}

// auditRow is one line of the journal, already put into words.
type auditRow struct {
	At     time.Time
	Actor  string
	Action string
	Target string
	IP     string
	Detail string
}

// auditChoice is one option in a filter above the journal.
type auditChoice struct {
	Value   string
	Label   string
	Current bool
}

// networkRow is one address a secret is pinned to.
type networkRow struct {
	Network string
	AddedAt time.Time
	AddedBy string
}
