package web

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"synsec/internal/store"
)

// auditPeriods are the ranges the page offers, in order.
var auditPeriods = []struct {
	Key   string
	Label string
	Span  time.Duration
}{
	{"24h", "Dernières 24 heures", 24 * time.Hour},
	{"7j", "7 derniers jours", 7 * 24 * time.Hour},
	{"30j", "30 derniers jours", 30 * 24 * time.Hour},
	{"tout", "Tout l'historique", 0},
}

// auditLabels turn an action into something readable. An action absent from
// the table is shown as it is stored, so a new one appears in the interface
// the day it is written rather than the day someone remembers to translate it.
var auditLabels = map[string]string{
	"auth.signin":    "Connexion",
	"auth.signout":   "Déconnexion",
	"auth.failed":    "Échec de connexion",
	"auth.throttled": "Connexions bloquées",
	"secret.read":    "Lecture d'un secret",
	"secret.write":   "Écriture d'un secret",
	"secret.delete":  "Suppression d'un secret",
	"vault.create":   "Création d'un coffre",
	"vault.delete":   "Suppression d'un coffre",
	"member.grant":   "Accès accordé",
	"member.revoke":  "Accès retiré",
	"share.grant":    "Secret partagé",
	"share.revoke":   "Partage retiré",
	"token.create":   "Jeton créé",
	"token.revoke":   "Jeton révoqué",
	"token.scope":    "Portée d'un jeton modifiée",
	"user.create":    "Compte créé",
	"user.password":  "Mot de passe changé",
	"user.delete":    "Compte supprimé",
	"access.denied":  "Accès refusé",
	"audit.grant":    "Journal ouvert à un compte",
	"audit.revoke":   "Accès au journal retiré",
}

// requireAuditReader gates the log.
//
// Someone who may not read it gets the same answer as for a page that does not
// exist: an administrator without the grant has no business knowing the log is
// there, let alone that they were refused.
func (s *Server) requireAuditReader(h http.HandlerFunc) http.HandlerFunc {
	return s.requireLogin(func(w http.ResponseWriter, r *http.Request) {
		if !canReadAuditFrom(r) {
			s.notFound(w, r)
			return
		}
		h(w, r)
	})
}

// requireRoot gates what only the account the server was set up with may do.
func (s *Server) requireRoot(h http.HandlerFunc) http.HandlerFunc {
	return s.requireLogin(func(w http.ResponseWriter, r *http.Request) {
		if !userFrom(r).IsRoot {
			s.notFound(w, r)
			return
		}
		h(w, r)
	})
}

// showAudit renders the log.
func (s *Server) showAudit(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	query := r.URL.Query()

	filter := store.AuditFilter{
		Action: strings.TrimSpace(query.Get("action")),
		Search: strings.TrimSpace(query.Get("q")),
		Limit:  200,
	}

	period := query.Get("periode")
	if period == "" {
		period = auditPeriods[1].Key // a week, the useful default
	}
	for _, p := range auditPeriods {
		if p.Key == period && p.Span > 0 {
			filter.Since = s.now().Add(-p.Span)
		}
	}

	entries, err := s.vault.DB().ListAudit(r.Context(), filter)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}
	actions, err := s.vault.DB().AuditActions(r.Context())
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	rows := make([]auditRow, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, auditRow{
			At:     e.At,
			Actor:  auditActor(e),
			Action: auditLabel(e.Action),
			Target: e.Target,
			IP:     e.IP,
			Detail: e.Detail,
		})
	}

	choices := make([]auditChoice, 0, len(actions)+1)
	for _, a := range actions {
		choices = append(choices, auditChoice{
			Value: a, Label: auditLabel(a), Current: a == filter.Action,
		})
	}

	periods := make([]auditChoice, 0, len(auditPeriods))
	for _, p := range auditPeriods {
		periods = append(periods, auditChoice{
			Value: p.Key, Label: p.Label, Current: p.Key == period,
		})
	}

	s.render(w, r, "audit.html", http.StatusOK, pageData{
		Title:        "Journal",
		Nav:          "journal",
		User:         &user,
		CSRF:         csrfFrom(r),
		Sealed:       s.vault.Sealed(),
		Audit:        rows,
		AuditActions: choices,
		AuditPeriods: periods,
		Search:       filter.Search,
		Truncated:    len(rows) >= filter.Limit,
		Notice:       query.Get("info"),
		Error:        query.Get("erreur"),
	})
}

// showAuditAccess lists the administrators the log was opened to.
func (s *Server) showAuditAccess(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	readers, err := s.vault.DB().ListAuditReaders(r.Context())
	if err != nil {
		s.fail(w, r, user, err)
		return
	}
	users, err := s.vault.DB().ListUsers(r.Context())
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	granted := make(map[string]bool, len(readers))
	rows := make([]memberRow, 0, len(readers))
	for _, reader := range readers {
		granted[reader.UserID] = true
		rows = append(rows, memberRow{
			UserID:      reader.UserID,
			Username:    reader.Username,
			DisplayName: reader.DisplayName,
			GrantedAt:   reader.GrantedAt,
			GrantedBy:   reader.GrantedBy,
		})
	}

	// Only administrators are offered: the log spans every vault, and handing
	// it to someone who cannot even manage accounts would make the grant a
	// larger privilege than the flag it is supposed to accompany.
	candidates := make([]userRow, 0, len(users))
	for _, u := range users {
		if !u.IsAdmin || u.IsRoot || granted[u.ID] {
			continue
		}
		candidates = append(candidates, userRow{
			ID: u.ID, Username: u.Username, DisplayName: u.DisplayName,
		})
	}

	s.render(w, r, "audit_access.html", http.StatusOK, pageData{
		Title:      "Accès au journal",
		Nav:        "journal",
		User:       &user,
		CSRF:       csrfFrom(r),
		Sealed:     s.vault.Sealed(),
		Members:    rows,
		Candidates: candidates,
		Notice:     r.URL.Query().Get("info"),
		Error:      r.URL.Query().Get("erreur"),
	})
}

// grantAuditAccess opens the log to an administrator.
func (s *Server) grantAuditAccess(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	const back = "/journal/acces"

	target, ok := s.auditTarget(w, r, back)
	if !ok {
		return
	}
	if !target.IsAdmin {
		s.redirectWithError(w, r, back,
			"Le journal ne s'ouvre qu'à un administrateur.")
		return
	}

	if err := s.vault.DB().GrantAuditReader(r.Context(), target.ID, user.Username); err != nil {
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "audit.grant", Target: target.Username,
	})
	s.redirectWithNotice(w, r, back,
		"« "+target.Username+" » peut désormais lire le journal.")
}

// revokeAuditAccess closes it again.
func (s *Server) revokeAuditAccess(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	const back = "/journal/acces"

	target, ok := s.auditTarget(w, r, back)
	if !ok {
		return
	}

	if err := s.vault.DB().RevokeAuditReader(r.Context(), target.ID); err != nil {
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "audit.revoke", Target: target.Username,
	})
	s.redirectWithNotice(w, r, back,
		"« "+target.Username+" » ne lit plus le journal.")
}

// auditTarget reads the account a grant form acts on.
func (s *Server) auditTarget(w http.ResponseWriter, r *http.Request, back string) (store.User, bool) {
	id := strings.TrimSpace(r.PostFormValue("user"))
	if id == "" {
		s.redirectWithError(w, r, back, "Aucun compte indiqué.")
		return store.User{}, false
	}

	target, err := s.vault.DB().User(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.redirectWithError(w, r, back, "Ce compte n'existe pas.")
			return store.User{}, false
		}
		s.fail(w, r, userFrom(r), err)
		return store.User{}, false
	}
	return target, true
}

// canReadAuditFrom reads the answer resolved by requireLogin.
func canReadAuditFrom(r *http.Request) bool {
	ok, _ := r.Context().Value(ctxCanReadAudit).(bool)
	return ok
}

// auditLabel turns a stored action into wording.
func auditLabel(action string) string {
	if label, ok := auditLabels[action]; ok {
		return label
	}
	return action
}

// auditActor names who did something, including the machines.
func auditActor(e store.AuditEntry) string {
	switch {
	case e.ActorLabel != "":
		return e.ActorLabel
	case e.ActorKind == store.ActorSystem:
		return "le serveur"
	default:
		return "inconnu"
	}
}
