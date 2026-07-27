package web

import (
	"errors"
	"net/http"
	"strings"

	"synsec/internal/store"
)

// Pinning a secret to an address decides who may read it, so it is a manager's
// right - the same kind of decision as handing out access.

// addNetwork restricts a secret to an address or block.
func (s *Server) addNetwork(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, _, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}

	name := strings.TrimSpace(r.PostFormValue("name"))
	secret, ok := s.secretOf(w, r, vault, name)
	if !ok {
		return
	}
	back := "/coffres/" + vault.ID + "/secret?name=" + urlEncode(secret.Name)

	network, err := store.ParseNetwork(r.PostFormValue("address"))
	if err != nil {
		s.redirectWithError(w, r, back,
			"Indique une adresse IP ou un bloc CIDR, par exemple 192.168.1.72 ou 192.168.1.0/24.")
		return
	}

	if err := s.vault.DB().AddSecretNetwork(r.Context(), secret.ID, network, user.Username); err != nil {
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "secret.pin", Target: secret.Name, Detail: network,
	})
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// removeNetwork lifts one restriction.
func (s *Server) removeNetwork(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	vault, _, ok := s.requireVault(w, r, store.RoleManager)
	if !ok {
		return
	}

	name := strings.TrimSpace(r.PostFormValue("name"))
	secret, ok := s.secretOf(w, r, vault, name)
	if !ok {
		return
	}
	back := "/coffres/" + vault.ID + "/secret?name=" + urlEncode(secret.Name)

	address := strings.TrimSpace(r.PostFormValue("address"))
	if err := s.vault.DB().RemoveSecretNetwork(r.Context(), secret.ID, address); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.redirectWithError(w, r, back, "Cette adresse n'était pas dans la liste.")
			return
		}
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "secret.unpin", Target: secret.Name, Detail: address,
	})
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// networksOf lists the addresses a secret is pinned to, for the secret page.
func (s *Server) networksOf(r *http.Request, secretID string) ([]networkRow, error) {
	networks, err := s.vault.DB().ListSecretNetworks(r.Context(), secretID)
	if err != nil {
		return nil, err
	}

	out := make([]networkRow, 0, len(networks))
	for _, n := range networks {
		out = append(out, networkRow{
			Network: n.Network,
			AddedAt: n.AddedAt,
			AddedBy: n.AddedBy,
		})
	}
	return out, nil
}
