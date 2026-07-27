package web

import (
	"net/http"

	"synsec/internal/store"
)

// showHome lists the vaults the visitor may see, and the secrets handed to
// them individually.
//
// Counting secrets touches no ciphertext: the metadata lives in its own table
// precisely so the front page costs nothing in cryptography.
func (s *Server) showHome(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	// Everyone, administrators included, sees only what has been granted to
	// them. A vault nobody shared is absent rather than locked: its name alone
	// can say more than its contents.
	vaults, err := s.vault.DB().ListVaultsForUser(r.Context(), user.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	// Split by owner, not by role. People say "Alice's vault" whatever they are
	// allowed to do in it, and sorting by role would make a vault jump from one
	// section to the other the day someone is promoted to manager.
	var mine, shared []vaultRow
	for _, v := range vaults {
		secrets, err := s.vault.DB().ListSecrets(r.Context(), v.ID, store.DefaultEnvironment)
		if err != nil {
			logError(r, err)
			secrets = nil
		}
		row := vaultRow{
			ID:          v.ID,
			Name:        v.Name,
			Description: v.Description,
			Secrets:     len(secrets),
			CreatedAt:   v.CreatedAt,
			Role:        v.Role,
			OwnerName:   v.OwnerName,
		}
		if v.OwnerID == user.ID {
			mine = append(mine, row)
		} else {
			shared = append(shared, row)
		}
	}

	loose, err := s.vault.DB().ListSharedSecrets(r.Context(), user.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}
	sharedSecrets := make([]sharedRow, 0, len(loose))
	for _, sec := range loose {
		sharedSecrets = append(sharedSecrets, sharedRow{
			VaultID:   sec.ProjectID,
			VaultName: sec.ProjectName,
			Name:      sec.Name,
			Label:     sec.Label,
			Role:      sec.Role,
			UpdatedAt: sec.UpdatedAt,
		})
	}

	s.render(w, r, "home.html", http.StatusOK, pageData{
		Title:        "Mes coffres",
		Nav:          "coffres",
		User:         &user,
		CSRF:         csrfFrom(r),
		Sealed:       s.vault.Sealed(),
		Vaults:       mine,
		SharedVaults: shared,
		Shared:       sharedSecrets,
		// Set by a redirect after a failed action. It is written by SYNSEC,
		// never by the visitor's own input, so it cannot be used to put
		// arbitrary text on someone else's screen.
		Error: r.URL.Query().Get("erreur"),
	})
}
