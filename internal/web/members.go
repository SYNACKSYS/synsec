package web

import (
	"errors"
	"net/http"
	"strings"

	"synsec/internal/store"
)

// Granting access is always a manager's right, over the whole vault.
//
// Letting someone re-share what was shared with them would turn a single
// handed-over password into a chain nobody can follow, and would let a
// recipient widen their own reach without the owner ever hearing about it.

// showMembers lists who may reach a vault, and offers to add someone.
func (s *Server) showMembers(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, role, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}

	members, err := s.vault.DB().ListVaultMembers(r.Context(), vault.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	candidates, err := s.candidates(r, memberIDs(members))
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	s.render(w, r, "members.html", http.StatusOK, pageData{
		Title:      "Membres de " + vault.Name,
		Nav:        "coffres",
		User:       &user,
		CSRF:       csrfFrom(r),
		Sealed:     s.vault.Sealed(),
		Vault:      &vaultRow{ID: vault.ID, Name: vault.Name},
		Members:    toMemberRows(members),
		Candidates: candidates,
		Role:       role,
		CanManage:  true,
		Error:      r.URL.Query().Get("erreur"),
	})
}

// addMember grants or changes someone's access to a vault.
func (s *Server) addMember(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, _, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}
	back := "/coffres/" + vault.ID + "/membres"

	target, role, ok := s.readGrant(w, r, back, true)
	if !ok {
		return
	}

	if err := s.vault.DB().SetVaultMember(r.Context(), vault.ID, target.ID, role, user.Username); err != nil {
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "vault.grant", Target: vault.Name,
		ProjectID: vault.ID,
		Detail:    target.Username + " → " + role.Label(),
	})
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// removeMember revokes someone's access to a vault.
func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, _, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}
	back := "/coffres/" + vault.ID + "/membres"

	targetID := strings.TrimSpace(r.PostFormValue("user"))
	members, err := s.vault.DB().ListVaultMembers(r.Context(), vault.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	// Removing the last manager would leave the vault with nobody able to
	// grant access to it again - recoverable only by a server administrator,
	// and baffling to everyone else.
	if lastManager(members, targetID) {
		s.redirectWithError(w, r, back,
			"C'est le dernier gestionnaire du coffre : nomme quelqu'un d'autre avant de le retirer.")
		return
	}

	if err := s.vault.DB().RemoveVaultMember(r.Context(), vault.ID, targetID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.redirectWithError(w, r, back, "Cette personne n'avait pas accès à ce coffre.")
			return
		}
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "vault.revoke", Target: vault.Name, Detail: targetID,
		ProjectID: vault.ID,
	})
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// showShares lists who one secret has been handed to individually.
func (s *Server) showShares(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, _, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}

	path := strings.TrimSpace(r.URL.Query().Get("name"))
	secret, ok := s.secretOf(w, r, vault, path)
	if !ok {
		return
	}

	shares, err := s.vault.DB().ListSecretShares(r.Context(), secret.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	candidates, err := s.candidates(r, memberIDs(shares))
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	s.render(w, r, "shares.html", http.StatusOK, pageData{
		Title:      "Partages de " + secret.Name,
		Nav:        "coffres",
		User:       &user,
		CSRF:       csrfFrom(r),
		Sealed:     s.vault.Sealed(),
		Vault:      &vaultRow{ID: vault.ID, Name: vault.Name},
		Secret:     &secretRow{Name: secret.Name},
		Members:    toMemberRows(shares),
		Candidates: candidates,
		CanManage:  true,
		Error:      r.URL.Query().Get("erreur"),
	})
}

// addShare hands one secret to one person.
func (s *Server) addShare(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, _, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}

	path := strings.TrimSpace(r.PostFormValue("name"))
	secret, ok := s.secretOf(w, r, vault, path)
	if !ok {
		return
	}
	back := "/coffres/" + vault.ID + "/partages?name=" + urlEncode(secret.Name)

	target, role, ok := s.readGrant(w, r, back, false)
	if !ok {
		return
	}

	if err := s.vault.DB().SetSecretShare(r.Context(), secret.ID, target.ID, role, user.Username); err != nil {
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "secret.share", Target: secret.Name,
		ProjectID: vault.ID,
		Detail:    target.Username + " → " + role.Label(),
	})
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// removeShare withdraws an individual share.
func (s *Server) removeShare(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, _, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}

	path := strings.TrimSpace(r.PostFormValue("name"))
	secret, ok := s.secretOf(w, r, vault, path)
	if !ok {
		return
	}
	back := "/coffres/" + vault.ID + "/partages?name=" + urlEncode(secret.Name)

	targetID := strings.TrimSpace(r.PostFormValue("user"))
	if err := s.vault.DB().RemoveSecretShare(r.Context(), secret.ID, targetID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.redirectWithError(w, r, back, "Ce secret n'était pas partagé avec cette personne.")
			return
		}
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "secret.unshare", Target: secret.Name, Detail: targetID,
		ProjectID: vault.ID,
	})
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// readGrant reads the person and role submitted by a grant form.
func (s *Server) readGrant(w http.ResponseWriter, r *http.Request, back string, allowManager bool) (store.User, store.Role, bool) {
	targetID := strings.TrimSpace(r.PostFormValue("user"))
	if targetID == "" {
		s.redirectWithError(w, r, back, "Choisis la personne à qui donner accès.")
		return store.User{}, store.RoleNone, false
	}

	role := store.Role(strings.TrimSpace(r.PostFormValue("role")))
	if !role.Valid() || (role == store.RoleManager && !allowManager) {
		s.redirectWithError(w, r, back, "Choisis un niveau d'accès valable.")
		return store.User{}, store.RoleNone, false
	}

	target, err := s.vault.DB().User(r.Context(), targetID)
	if err != nil {
		s.redirectWithError(w, r, back, "Ce compte n'existe pas.")
		return store.User{}, store.RoleNone, false
	}
	return target, role, true
}

// secretOf resolves a secret inside a vault the caller already manages.
func (s *Server) secretOf(w http.ResponseWriter, r *http.Request, vault store.Project, path string) (store.Secret, bool) {
	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: path}

	secret, err := s.vault.DB().SecretMeta(r.Context(), loc)
	if err != nil {
		s.notFound(w, r)
		return store.Secret{}, false
	}
	return secret, true
}

// candidates lists the accounts not already granted, so the form offers only
// people it makes sense to add.
func (s *Server) candidates(r *http.Request, already map[string]bool) ([]userRow, error) {
	users, err := s.vault.DB().ListUsers(r.Context())
	if err != nil {
		return nil, err
	}

	out := make([]userRow, 0, len(users))
	for _, u := range users {
		if already[u.ID] {
			continue
		}
		out = append(out, userRow{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName})
	}
	return out, nil
}

func memberIDs(members []store.Membership) map[string]bool {
	out := make(map[string]bool, len(members))
	for _, m := range members {
		out[m.UserID] = true
	}
	return out
}

func toMemberRows(members []store.Membership) []memberRow {
	out := make([]memberRow, 0, len(members))
	for _, m := range members {
		out = append(out, memberRow{
			UserID:      m.UserID,
			Username:    m.Username,
			DisplayName: m.DisplayName,
			Role:        m.Role,
			GrantedAt:   m.GrantedAt,
			GrantedBy:   m.GrantedBy,
		})
	}
	return out
}

// lastManager reports whether removing targetID would leave the vault without
// anyone able to grant access to it.
func lastManager(members []store.Membership, targetID string) bool {
	target, others := false, 0
	for _, m := range members {
		if m.Role != store.RoleManager {
			continue
		}
		if m.UserID == targetID {
			target = true
			continue
		}
		others++
	}
	return target && others == 0
}
