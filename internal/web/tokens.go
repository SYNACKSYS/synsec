package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"synsec/internal/auth"
	"synsec/internal/store"
)

// Connecting a device is a manager's right: a token stands in for a password,
// so handing one out is the same kind of decision as adding a member - even
// when it is narrowed to a single secret.

// showTokens lists the devices connected to a vault.
func (s *Server) showTokens(w http.ResponseWriter, r *http.Request) {
	vault, _, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}
	s.renderTokens(w, r, vault, "", http.StatusOK)
}

// createToken mints a token and shows it once.
//
// Rendered directly rather than redirected: the plaintext exists for this one
// response and must not travel in a URL, where it would land in the browser
// history and in any proxy log on the way.
func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, _, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}
	back := "/coffres/" + vault.ID + "/appareils"

	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		s.redirectWithError(w, r, back, "Donne un nom à l'appareil.")
		return
	}

	id, err := store.NewID()
	if err != nil {
		s.fail(w, r, user, err)
		return
	}
	plaintext, hash, err := auth.NewServiceToken(id)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	scope, ok := s.checkedSecrets(r, vault.ID)
	if !ok {
		s.redirectWithError(w, r, back, "Un des secrets cochés n'existe pas dans ce coffre.")
		return
	}

	tok := store.ServiceToken{
		ID:          id,
		Name:        name,
		ProjectID:   vault.ID,
		Env:         store.DefaultEnvironment,
		CanWrite:    r.PostFormValue("can_write") != "",
		IPAllowlist: splitAddresses(r.PostFormValue("addresses")),
		Secrets:     scope,
		CreatedBy:   user.Username,
	}
	if days := parseDays(r.PostFormValue("expires")); days > 0 {
		tok.ExpiresAt = s.now().AddDate(0, 0, days)
	}

	for _, entry := range tok.IPAllowlist {
		if _, err := store.ParseNetwork(entry); err != nil {
			s.redirectWithError(w, r, back,
				"« "+entry+" » n'est ni une adresse IP ni un bloc CIDR.")
			return
		}
	}

	if err := s.vault.DB().CreateServiceToken(r.Context(), &tok, hash); err != nil {
		if errors.Is(err, store.ErrLabel) {
			s.redirectWithError(w, r, back, labelProblem(err))
			return
		}
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "token.create", Target: vault.Name, Detail: name,
	})
	s.renderTokens(w, r, vault, plaintext, http.StatusOK)
}

// revokeToken disables a token without deleting it, so the audit log keeps
// pointing at something that still has a name.
func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, _, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}
	back := "/coffres/" + vault.ID + "/appareils"

	id := strings.TrimSpace(r.PostFormValue("token"))
	tok, _, err := s.vault.DB().ServiceToken(r.Context(), id)
	if err != nil || tok.ProjectID != vault.ID {
		// A token belonging to another vault is not this manager's business.
		s.redirectWithError(w, r, back, "Cet appareil n'existe pas dans ce coffre.")
		return
	}

	if err := s.vault.DB().RevokeServiceToken(r.Context(), id, s.now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.redirectWithError(w, r, back, "Cet appareil était déjà révoqué.")
			return
		}
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "token.revoke", Target: vault.Name, Detail: tok.Name,
	})
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// showTokenScope renders what one device may reach.
func (s *Server) showTokenScope(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, _, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}

	tok, ok := s.tokenOfVault(w, r, vault, strings.TrimSpace(r.URL.Query().Get("token")))
	if !ok {
		return
	}

	secrets, err := s.scopeChoices(r, vault.ID, tok.Secrets)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	s.render(w, r, "token_scope.html", http.StatusOK, pageData{
		Title:     "Portée de " + tok.Name,
		Nav:       "coffres",
		User:      &user,
		CSRF:      csrfFrom(r),
		Sealed:    s.vault.Sealed(),
		Vault:     &vaultRow{ID: vault.ID, Name: vault.Name},
		Token:     &tokenRow{ID: tok.ID, Name: tok.Name, Secrets: tok.Secrets},
		Secrets:   secrets,
		CanManage: true,
		Error:     r.URL.Query().Get("erreur"),
	})
}

// saveTokenScope narrows a device, or opens it back to the whole vault.
func (s *Server) saveTokenScope(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, _, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}
	back := "/coffres/" + vault.ID + "/appareils"

	tok, ok := s.tokenOfVault(w, r, vault, strings.TrimSpace(r.PostFormValue("token")))
	if !ok {
		return
	}

	scope, valid := s.checkedSecrets(r, vault.ID)
	if !valid {
		s.redirectWithError(w, r, back, "Un des secrets cochés n'existe pas dans ce coffre.")
		return
	}

	if err := s.vault.DB().SetTokenSecrets(r.Context(), tok.ID, scope); err != nil {
		s.fail(w, r, user, err)
		return
	}

	detail := tok.Name + " : tout le coffre"
	if len(scope) > 0 {
		detail = tok.Name + " : " + strings.Join(scope, ", ")
	}
	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "token.scope", Target: vault.Name, Detail: detail,
	})
	s.redirectWithNotice(w, r, back, "Portée de « "+tok.Name+" » enregistrée.")
}

// tokenOfVault reads the device a form acts on, refusing one that belongs
// somewhere else - a manager here is not a manager everywhere.
func (s *Server) tokenOfVault(w http.ResponseWriter, r *http.Request, vault store.Project, id string) (store.ServiceToken, bool) {
	tok, _, err := s.vault.DB().ServiceToken(r.Context(), id)
	if err != nil || tok.ProjectID != vault.ID {
		s.redirectWithError(w, r, "/coffres/"+vault.ID+"/appareils",
			"Cet appareil n'existe pas dans ce coffre.")
		return store.ServiceToken{}, false
	}
	return tok, true
}

// checkedSecrets reads the boxes ticked on a scope form. The false result
// means one of them names something this vault does not hold.
func (s *Server) checkedSecrets(r *http.Request, projectID string) ([]string, bool) {
	checked := r.PostForm["secret"]
	if len(checked) == 0 {
		return nil, true
	}

	found, err := s.vault.DB().ListSecrets(r.Context(), projectID, store.DefaultEnvironment)
	if err != nil {
		return nil, false
	}
	exists := make(map[string]bool, len(found))
	for _, sec := range found {
		exists[sec.Name] = true
	}

	out := make([]string, 0, len(checked))
	for _, name := range checked {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		if !exists[name] {
			return nil, false
		}
		out = append(out, name)
	}
	return out, true
}

// scopeChoices lists the vault's secrets, marking those already in scope.
func (s *Server) scopeChoices(r *http.Request, projectID string, scope []string) ([]secretRow, error) {
	found, err := s.vault.DB().ListSecrets(r.Context(), projectID, store.DefaultEnvironment)
	if err != nil {
		return nil, err
	}

	inScope := make(map[string]bool, len(scope))
	for _, name := range scope {
		inScope[name] = true
	}

	rows := make([]secretRow, 0, len(found))
	for _, sec := range found {
		rows = append(rows, secretRow{
			Name:      sec.Name,
			Label:     sec.Label,
			Version:   sec.CurrentVersion,
			UpdatedAt: sec.UpdatedAt,
			InScope:   inScope[sec.Name],
		})
	}
	return rows, nil
}

func (s *Server) renderTokens(w http.ResponseWriter, r *http.Request, vault store.Project, fresh string, status int) {
	user := userFrom(r)

	tokens, err := s.vault.DB().ListServiceTokens(r.Context(), vault.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}
	// The creation form offers the vault's secrets as boxes to tick.
	secrets, err := s.scopeChoices(r, vault.ID, nil)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	now := s.now()
	rows := make([]tokenRow, 0, len(tokens))
	for _, tok := range tokens {
		rows = append(rows, tokenRow{
			ID:         tok.ID,
			Name:       tok.Name,
			CanWrite:   tok.CanWrite,
			Secrets:    tok.Secrets,
			State:      tokenState(tok, now),
			Live:       tok.Live(now),
			Addresses:  strings.Join(tok.IPAllowlist, ", "),
			ExpiresAt:  tok.ExpiresAt,
			LastUsedAt: tok.LastUsedAt,
		})
	}

	s.render(w, r, "tokens.html", status, pageData{
		Title:     "Appareils de " + vault.Name,
		Nav:       "coffres",
		User:      &user,
		CSRF:      csrfFrom(r),
		Sealed:    s.vault.Sealed(),
		Vault:     &vaultRow{ID: vault.ID, Name: vault.Name},
		Tokens:    rows,
		Secrets:   secrets,
		NewToken:  fresh,
		Host:      s.publicHost(r),
		CanManage: true,
		Notice:    r.URL.Query().Get("info"),
		Error:     r.URL.Query().Get("erreur"),
	})
}

func tokenState(tok store.ServiceToken, now time.Time) string {
	switch {
	case !tok.RevokedAt.IsZero():
		return "révoqué"
	case !tok.ExpiresAt.IsZero() && !tok.ExpiresAt.After(now):
		return "expiré"
	default:
		return "actif"
	}
}

// parseDays reads the validity chosen in the form. Anything unreadable means
// no expiry, which is the form's own default.
func parseDays(raw string) int {
	days, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || days < 0 {
		return 0
	}
	return days
}

// splitAddresses reads a comma-separated allowlist.
func splitAddresses(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
