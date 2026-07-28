package web

import (
	"net/http"
	"strings"

	"synsec/internal/store"
)

// Finding a secret without remembering which vault it is in.
//
// Built on the same two calls the front page uses - the vaults this account may
// see, then the secrets in each - rather than on a query of its own. Access
// control that is written twice is access control that will disagree with
// itself eventually, and the half that leaks is the one nobody tested.
//
// Names and labels only. Searching values would mean decrypting every secret in
// every vault on each keystroke, which is both slow and exactly the kind of
// wholesale read the audit log exists to make visible.

// searchLimit bounds what one page shows. A household will never reach it; the
// cap is there so a query matching everything cannot turn into an enormous
// page.
const searchLimit = 100

func (s *Server) showSearch(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	query := strings.TrimSpace(r.URL.Query().Get("q"))

	data := pageData{
		Title:  "Recherche",
		Nav:    "recherche",
		User:   &user,
		CSRF:   csrfFrom(r),
		Sealed: s.vault.Sealed(),
		Search: query,
	}
	if query == "" {
		s.render(w, r, "search.html", http.StatusOK, data)
		return
	}

	found, truncated, err := s.searchSecrets(r, user, query)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}
	data.Shared = found
	data.Truncated = truncated
	s.render(w, r, "search.html", http.StatusOK, data)
}

// searchSecrets walks what this account can reach and keeps what matches.
func (s *Server) searchSecrets(r *http.Request, user store.User, query string) ([]sharedRow, bool, error) {
	needle := fold(query)

	vaults, err := s.vault.DB().ListVaultsForUser(r.Context(), user.ID)
	if err != nil {
		return nil, false, err
	}

	var out []sharedRow
	seen := make(map[string]bool)

	keep := func(row sharedRow) {
		key := row.VaultID + "/" + row.Name
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, row)
	}

	for _, vault := range vaults {
		secrets, err := s.vault.DB().ListSecrets(r.Context(), vault.ID, store.DefaultEnvironment)
		if err != nil {
			// One unreadable vault must not empty the whole page.
			logError(r, err)
			continue
		}
		for _, secret := range secrets {
			if !matches(needle, secret.Name, secret.Label) {
				continue
			}
			keep(sharedRow{
				VaultID:   vault.ID,
				VaultName: vault.Name,
				Name:      secret.Name,
				Label:     secret.Label,
				Role:      vault.Role,
				UpdatedAt: secret.UpdatedAt,
			})
		}
	}

	// Secrets handed over one by one, outside any vault this account belongs to.
	loose, err := s.vault.DB().ListSharedSecrets(r.Context(), user.ID)
	if err != nil {
		return nil, false, err
	}
	for _, secret := range loose {
		if !matches(needle, secret.Name, secret.Label) {
			continue
		}
		keep(sharedRow{
			VaultID:   secret.ProjectID,
			VaultName: secret.ProjectName,
			Name:      secret.Name,
			Label:     secret.Label,
			Role:      secret.Role,
			UpdatedAt: secret.UpdatedAt,
		})
	}

	if len(out) > searchLimit {
		return out[:searchLimit], true, nil
	}
	return out, false, nil
}

func matches(needle, name, label string) bool {
	return strings.Contains(fold(name), needle) || strings.Contains(fold(label), needle)
}

// fold puts a string into the form comparisons are made in: lower case, and
// without the accents somebody may or may not have typed.
//
// A short table rather than a Unicode normalisation library, because the
// alternative is a dependency and the alphabet this interface is written in is
// known. A letter that is not in the table simply compares as itself.
func fold(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for _, r := range strings.ToLower(s) {
		switch r {
		case 'à', 'â', 'ä', 'á', 'ã', 'å':
			b.WriteRune('a')
		case 'ç':
			b.WriteRune('c')
		case 'è', 'é', 'ê', 'ë':
			b.WriteRune('e')
		case 'î', 'ï', 'ì', 'í':
			b.WriteRune('i')
		case 'ô', 'ö', 'ò', 'ó', 'õ':
			b.WriteRune('o')
		case 'ù', 'û', 'ü', 'ú':
			b.WriteRune('u')
		case 'ÿ', 'ý':
			b.WriteRune('y')
		case 'ñ':
			b.WriteRune('n')
		case 'œ':
			b.WriteString("oe")
		case 'æ':
			b.WriteString("ae")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
