package web

import (
	"errors"
	"net/http"
	"strings"

	"synsec/internal/auth"
	"synsec/internal/store"
)

// requireAdmin gates the account pages.
//
// Administering accounts is the one thing the flag still confers: it opens no
// vault and reveals no secret. Someone who is not an administrator gets the
// same answer as for a page that does not exist, so the section is not even
// advertised to them.
func (s *Server) requireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return s.requireLogin(func(w http.ResponseWriter, r *http.Request) {
		if !userFrom(r).IsAdmin {
			s.notFound(w, r)
			return
		}
		h(w, r)
	})
}

// showAccounts lists the accounts on this server.
func (s *Server) showAccounts(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	users, err := s.vault.DB().ListUsers(r.Context())
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	rows := make([]accountRow, 0, len(users))
	for _, u := range users {
		rows = append(rows, accountRow{
			ID:          u.ID,
			Username:    u.Username,
			DisplayName: u.DisplayName,
			IsAdmin:     u.IsAdmin,
			IsRoot:      u.IsRoot,
			CreatedAt:   u.CreatedAt,
			LastLoginAt: u.LastLoginAt,
			IsSelf:      u.ID == user.ID,
		})
	}

	s.render(w, r, "accounts.html", http.StatusOK, pageData{
		Title:    "Comptes",
		Nav:      "comptes",
		User:     &user,
		CSRF:     csrfFrom(r),
		Sealed:   s.vault.Sealed(),
		Accounts: rows,
		Notice:   r.URL.Query().Get("info"),
		Error:    r.URL.Query().Get("erreur"),
	})
}

// createAccount adds an account.
func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	const back = "/comptes"

	username := strings.TrimSpace(r.PostFormValue("username"))
	if username == "" {
		s.redirectWithError(w, r, back, "Donne un nom d'utilisateur.")
		return
	}

	cred, err := auth.HashPassword(r.PostFormValue("password"))
	if err != nil {
		s.redirectWithError(w, r, back, passwordProblem(err))
		return
	}

	display := strings.TrimSpace(r.PostFormValue("display_name"))
	if display == "" {
		display = username
	}

	account := store.User{
		Username:    username,
		DisplayName: display,
		IsAdmin:     r.PostFormValue("is_admin") != "",
	}
	if err := s.vault.DB().CreateUser(r.Context(), &account, cred); err != nil {
		if store.IsConstraintViolation(err) {
			s.redirectWithError(w, r, back, "Un compte porte déjà ce nom.")
			return
		}
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "user.create", Target: account.Username,
	})
	s.redirectWithNotice(w, r, back,
		"Compte « "+account.Username+" » créé. Transmets-lui son mot de passe, il pourra le changer ensuite.")
}

// showPasswordForm asks for one account's new password.
//
// Its own page rather than a box under the list: a form that picks its target
// from a dropdown is one mis-click away from resetting the wrong person's
// password, and the row the administrator came from already says who.
func (s *Server) showPasswordForm(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	id := strings.TrimSpace(r.URL.Query().Get("user"))
	target, err := s.vault.DB().User(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.notFound(w, r)
			return
		}
		s.fail(w, r, user, err)
		return
	}

	s.render(w, r, "password.html", http.StatusOK, pageData{
		Title:  "Mot de passe",
		Nav:    "comptes",
		User:   &user,
		CSRF:   csrfFrom(r),
		Sealed: s.vault.Sealed(),
		Account: &accountRow{
			ID:          target.ID,
			Username:    target.Username,
			DisplayName: target.DisplayName,
			IsAdmin:     target.IsAdmin,
			IsSelf:      target.ID == user.ID,
		},
		Error: r.URL.Query().Get("erreur"),
	})
}

// resetPassword sets a new password for an account.
func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	const back = "/comptes"

	target, ok := s.targetAccount(w, r, back)
	if !ok {
		return
	}

	cred, err := auth.HashPassword(r.PostFormValue("password"))
	if err != nil {
		// Back to the form for this account, not to the list: the target is
		// already settled and retyping is all that is left to do.
		http.Redirect(w, r, "/comptes/motdepasse?user="+urlEncode(target.ID)+
			"&erreur="+urlEncode(passwordProblem(err)), http.StatusSeeOther)
		return
	}

	if err := s.vault.DB().SetUserCredentials(r.Context(), target.ID, cred); err != nil {
		s.fail(w, r, user, err)
		return
	}
	// A password changed because it leaked would leave the leak in place if
	// the open browsers kept working.
	if err := s.vault.DB().DeleteUserSessions(r.Context(), target.ID); err != nil {
		logError(r, err)
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "user.password", Target: target.Username,
	})
	s.redirectWithNotice(w, r, back,
		"Mot de passe de « "+target.Username+" » changé. Toutes ses sessions sont fermées.")
}

// deleteAccount removes an account.
func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	const back = "/comptes"

	target, ok := s.targetAccount(w, r, back)
	if !ok {
		return
	}
	if target.ID == user.ID {
		s.redirectWithError(w, r, back, "Tu ne peux pas supprimer ton propre compte.")
		return
	}

	if reason, blocked := s.deletionBlocked(r, target); blocked {
		s.redirectWithError(w, r, back, reason)
		return
	}

	if err := s.vault.DB().DeleteUser(r.Context(), target.ID); err != nil {
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "user.delete", Target: target.Username,
	})
	s.redirectWithNotice(w, r, back, "Compte « "+target.Username+" » supprimé.")
}

// deletionBlocked reports the reason an account cannot be removed, if any.
func (s *Server) deletionBlocked(r *http.Request, target store.User) (string, bool) {
	// The account the server was set up with holds the audit log and decides
	// who else may read it. Nothing can take its place afterwards, so removing
	// it would leave that door shut for good.
	if target.IsRoot {
		return "C'est le compte principal du serveur, il ne se supprime pas.", true
	}

	// Removing the last administrator would leave nobody able to manage
	// accounts at all.
	if target.IsAdmin {
		users, err := s.vault.DB().ListUsers(r.Context())
		if err != nil {
			logError(r, err)
			return "Impossible de vérifier les administrateurs restants.", true
		}
		admins := 0
		for _, u := range users {
			if u.IsAdmin {
				admins++
			}
		}
		if admins <= 1 {
			return "C'est le dernier administrateur : nomme quelqu'un d'autre avant de le supprimer.", true
		}
	}

	// And since an administrator no longer sees vaults nobody shared with
	// them, removing the only manager of a vault would strand it for good.
	stranded, err := s.vault.DB().SoleManagerVaults(r.Context(), target.ID)
	if err != nil {
		logError(r, err)
		return "Impossible de vérifier les coffres de ce compte.", true
	}
	if len(stranded) > 0 {
		names := make([]string, 0, len(stranded))
		for _, p := range stranded {
			names = append(names, "« "+p.Name+" »")
		}
		return "Ce compte est le seul gestionnaire de " + strings.Join(names, ", ") +
			". Donne la gestion à quelqu'un d'autre avant de le supprimer.", true
	}
	return "", false
}

// targetAccount reads the account a form acts on.
func (s *Server) targetAccount(w http.ResponseWriter, r *http.Request, back string) (store.User, bool) {
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

// passwordProblem turns a rejection into something worth reading.
func passwordProblem(err error) string {
	switch {
	case errors.Is(err, auth.ErrPasswordTooShort):
		return "Le mot de passe doit faire au moins 10 caractères."
	case errors.Is(err, auth.ErrPasswordTooLong):
		return "Ce mot de passe est trop long."
	default:
		return "Ce mot de passe n'a pas été accepté."
	}
}

// redirectWithNotice sends the visitor back with a confirmation.
func (s *Server) redirectWithNotice(w http.ResponseWriter, r *http.Request, to, message string) {
	http.Redirect(w, r, to+"?info="+urlEncode(message), http.StatusSeeOther)
}
