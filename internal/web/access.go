package web

import (
	"context"
	"errors"
	"net/http"

	"synsec/internal/store"
)

// vaultRole returns what a person may do with a whole vault.
//
// Administering the server and reading other people's secrets are separate
// things: an administrator creates accounts, installs the service and rotates
// keys, and sees nothing in a vault nobody granted them. Their own vaults are
// theirs; everyone else's are invisible.
//
// This is a rule, not a guarantee. An administrator holds the root key, can
// reset anyone's password and can read every secret from the command line,
// where none of these checks apply. What it buys is that casual curiosity
// takes a deliberate, audited act - not that the boundary cannot be crossed.
func (s *Server) vaultRole(ctx context.Context, user store.User, projectID string) (store.Role, error) {
	return s.vault.DB().VaultRole(ctx, projectID, user.ID)
}

// secretRole returns what a person may do with one secret: whatever the vault
// grants them, raised by any individual share.
func (s *Server) secretRole(ctx context.Context, user store.User, projectID, secretID string) (store.Role, error) {
	fromVault, err := s.vaultRole(ctx, user, projectID)
	if err != nil {
		return store.RoleNone, err
	}
	if fromVault == store.RoleManager {
		return fromVault, nil
	}

	fromShare, err := s.vault.DB().SecretShareRole(ctx, secretID, user.ID)
	if err != nil {
		return store.RoleNone, err
	}
	return store.Higher(fromVault, fromShare), nil
}

// requireVault resolves the vault named in the URL and checks the visitor
// holds at least the role needed.
//
// Anything they may not reach answers 404, never 403. A 403 would confirm that
// a vault exists behind that identifier, which is precisely what someone
// probing wants to learn; a household member poking at URLs should not be able
// to map what they cannot open.
func (s *Server) requireVault(w http.ResponseWriter, r *http.Request, needed store.Role) (store.Project, store.Role, bool) {
	user := userFrom(r)

	vault, err := s.vault.DB().Project(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.notFound(w, r)
			return store.Project{}, store.RoleNone, false
		}
		s.fail(w, r, user, err)
		return store.Project{}, store.RoleNone, false
	}

	role, err := s.vaultRole(r.Context(), user, vault.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return store.Project{}, store.RoleNone, false
	}
	if !role.AtLeast(needed) {
		s.notFound(w, r)
		return store.Project{}, store.RoleNone, false
	}
	return vault, role, true
}

// requireSecret resolves an existing secret and checks access, counting
// individual shares as well as vault membership.
//
// The vault itself is looked up without any check, on purpose: someone handed
// a single secret has no role on its vault, and gating on the vault first
// would lock them out of the very thing that was shared with them.
func (s *Server) requireSecret(w http.ResponseWriter, r *http.Request, path string, needed store.Role) (store.Project, store.Secret, store.Role, bool) {
	user := userFrom(r)

	vault, err := s.vault.DB().Project(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.notFound(w, r)
			return store.Project{}, store.Secret{}, store.RoleNone, false
		}
		s.fail(w, r, user, err)
		return store.Project{}, store.Secret{}, store.RoleNone, false
	}

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: path}
	secret, err := s.vault.DB().SecretMeta(r.Context(), loc)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.notFound(w, r)
			return store.Project{}, store.Secret{}, store.RoleNone, false
		}
		s.fail(w, r, user, err)
		return store.Project{}, store.Secret{}, store.RoleNone, false
	}

	role, err := s.secretRole(r.Context(), user, vault.ID, secret.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return store.Project{}, store.Secret{}, store.RoleNone, false
	}
	if !role.AtLeast(needed) {
		s.notFound(w, r)
		return store.Project{}, store.Secret{}, store.RoleNone, false
	}
	return vault, secret, role, true
}

// notFound is the single answer to everything a visitor may not see, whether
// it is absent or merely forbidden.
func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	s.render(w, r, "message.html", http.StatusNotFound, pageData{
		Title: "Introuvable",
		Nav:   "coffres",
		User:  &user,
		CSRF:  csrfFrom(r),
		Error: "Cette page n'existe pas, ou tu n'y as pas accès.",
	})
}
