package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"synsec/internal/store"
)

// The role model, exercised rather than read.
//
// Three roles on a vault - lecture, écriture, gestion - plus a share on a
// single secret, plus the administrator flag, plus the root account. The rules
// live in several files; what matters is what they add up to at the door.

// asRole signs someone in with a role on a vault and returns the harness ready
// to act as them.
func (h *harness) asRole(t *testing.T, username string, vaultID string, role store.Role) {
	t.Helper()
	u := h.addUser(t, username)
	if err := h.manager.DB().SetVaultMember(context.Background(), vaultID, u.ID, role, "cyril"); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}
	h.signInAs(t, username)
}

func TestWhatEachRoleMayDo(t *testing.T) {
	type attempt struct {
		what   string
		do     func(h *harness, vaultID string) *http.Response
		reader bool // permitted for a reader
		writer bool
		manage bool
	}

	attempts := []attempt{
		{"ouvrir le coffre", func(h *harness, v string) *http.Response {
			return h.get(t, "/coffres/"+v)
		}, true, true, true},

		{"lire un secret", func(h *harness, v string) *http.Response {
			return h.get(t, "/coffres/"+v+"/secret?name=mqtt")
		}, true, true, true},

		{"écrire un secret", func(h *harness, v string) *http.Response {
			return h.post(t, "/coffres/"+v+"/secret", url.Values{
				"csrf": {h.csrf(t)}, "name": {"nouveau"}, "value": {"x"},
			})
		}, false, true, true},

		{"supprimer un secret", func(h *harness, v string) *http.Response {
			return h.post(t, "/coffres/"+v+"/secret/supprimer", url.Values{
				"csrf": {h.csrf(t)}, "name": {"mqtt"},
			})
		}, false, true, true},

		{"voir les membres", func(h *harness, v string) *http.Response {
			return h.get(t, "/coffres/"+v+"/membres")
		}, false, false, true},

		{"voir les appareils", func(h *harness, v string) *http.Response {
			return h.get(t, "/coffres/"+v+"/appareils")
		}, false, false, true},
	}

	roles := []struct {
		name string
		role store.Role
		may  func(a attempt) bool
	}{
		{"lecteur", store.RoleReader, func(a attempt) bool { return a.reader }},
		{"redacteur", store.RoleWriter, func(a attempt) bool { return a.writer }},
		{"gestionnaire", store.RoleManager, func(a attempt) bool { return a.manage }},
	}

	for _, r := range roles {
		for _, a := range attempts {
			h := newHarness(t)
			h.signIn(t)
			vault := h.newVault(t, "Maison")
			h.writeVersions(t, vault.ID, "mqtt", "s3cr3t")
			h.asRole(t, "temoin", vault.ID, r.role)

			resp := a.do(h, vault.ID)
			refused := resp.StatusCode == http.StatusNotFound ||
				strings.Contains(resp.Header.Get("Location"), "erreur=")

			if r.may(a) && refused {
				t.Errorf("%s : %q refusé alors qu'il devrait passer (%d)", r.name, a.what, resp.StatusCode)
			}
			if !r.may(a) && !refused {
				t.Errorf("%s : %q accepté alors qu'il devrait être refusé (%d)", r.name, a.what, resp.StatusCode)
			}
		}
	}
}

// A refusal answers 404, never 403: a 403 confirms that something exists
// behind an identifier, which is what somebody probing wants to learn.
func TestRefusalsNeverConfirmExistence(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	h.writeVersions(t, vault.ID, "mqtt", "s3cr3t")

	h.addUser(t, "etranger")
	h.signInAs(t, "etranger")

	for _, path := range []string{
		"/coffres/" + vault.ID,
		"/coffres/" + vault.ID + "/secret?name=mqtt",
		"/coffres/" + vault.ID + "/membres",
		"/coffres/" + vault.ID + "/appareils",
		"/coffres/aaaaaaaaaaaaaaaa",
	} {
		if code := h.get(t, path).StatusCode; code != http.StatusNotFound {
			t.Errorf("%s répond %d, attendu 404", path, code)
		}
	}
}

// A share on one secret grants that secret and nothing around it, and never
// the right to pass it on.
func TestAShareStaysOnItsSecret(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	h.writeVersions(t, vault.ID, "mqtt", "s3cr3t")
	h.writeVersions(t, vault.ID, "camera", "autre")
	alice := h.addUser(t, "alice")

	h.post(t, "/coffres/"+vault.ID+"/partages", url.Values{
		"csrf": {h.csrf(t)}, "name": {"mqtt"},
		"user": {alice.ID}, "role": {string(store.RoleReader)},
	})

	h.signInAs(t, "alice")
	if code := h.get(t, "/coffres/"+vault.ID+"/secret?name=mqtt").StatusCode; code != http.StatusOK {
		t.Fatalf("le secret partagé est inaccessible (%d)", code)
	}
	for _, path := range []string{
		"/coffres/" + vault.ID,
		"/coffres/" + vault.ID + "/secret?name=camera",
		"/coffres/" + vault.ID + "/partages?name=mqtt",
	} {
		if code := h.get(t, path).StatusCode; code != http.StatusNotFound {
			t.Errorf("%s répond %d à une personne qui n'a qu'un secret", path, code)
		}
	}
}

// The administrator flag governs accounts, never vaults.
func TestAnAdministratorSeesNoVaultOfSomebodyElse(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	h.addAdmin(t, "admin")
	h.signInAs(t, "admin")

	if code := h.get(t, "/comptes").StatusCode; code != http.StatusOK {
		t.Fatalf("un administrateur n'atteint pas la page des comptes (%d)", code)
	}
	if code := h.get(t, "/coffres/"+vault.ID).StatusCode; code != http.StatusNotFound {
		t.Fatalf("un administrateur voit un coffre qu'on ne lui a pas partagé (%d)", code)
	}
}

// And what only the root account may do stays with it.
func TestOnlyTheRootAccountHoldsTheServerWideThings(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	h.addAdmin(t, "admin")
	h.signInAs(t, "admin")

	for _, path := range []string{"/journal", "/journal/acces", "/parametres/serveur"} {
		if code := h.get(t, path).StatusCode; code != http.StatusNotFound {
			t.Errorf("%s répond %d à un administrateur ordinaire", path, code)
		}
	}
}
