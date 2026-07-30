package web

import (
	"net/url"
	"strings"
	"testing"

	"synsec/internal/store"
)

// Who opened a secret, shown on the secret's own page.
//
// The journal answers this for the whole server and belongs to one account.
// This is the same question asked about one secret, by the person responsible
// for it - which is a different question, and a different set of eyes.

func TestASecretPageShowsWhoOpenedIt(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	h.writeVersions(t, vault.ID, "mot_de_passe_mqtt", "s3cr3t")

	// Someone else, with access, opens it.
	alice := h.addUser(t, "alice")
	if err := h.manager.DB().SetVaultMember(t.Context(), vault.ID, alice.ID, store.RoleReader, "cyril"); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}
	h.signInAs(t, "alice")
	h.get(t, "/coffres/"+vault.ID+"/secret?name=mot_de_passe_mqtt")

	h.signInAs(t, "cyril")
	page := body(t, h.get(t, "/coffres/"+vault.ID+"/secret?name=mot_de_passe_mqtt"))

	if !strings.Contains(page, "Qui l'a ouvert") {
		t.Fatal("la page du secret ne montre pas les consultations")
	}
	if !strings.Contains(page, "alice") {
		t.Error("la lecture d'alice n'apparaît pas")
	}
}

// The list belongs to this secret, in this vault. Two vaults may hold a
// "mot_de_passe_mqtt" and telling one's readers about the other would be worse
// than showing nothing.
func TestViewsDoNotCrossVaults(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	mine := h.newVault(t, "Maison")
	h.writeVersions(t, mine.ID, "mot_de_passe_mqtt", "s3cr3t")

	// Alice keeps her own vault, with a secret of exactly the same name, and
	// reads hers.
	h.addUser(t, "alice")
	h.signInAs(t, "alice")
	resp := h.post(t, "/coffres", url.Values{"csrf": {h.csrf(t)}, "name": {"Perso"}})
	hers := strings.TrimPrefix(resp.Header.Get("Location"), "/coffres/")
	h.post(t, "/coffres/"+hers+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "name": {"mot_de_passe_mqtt"}, "value": {"le sien"},
	})
	h.get(t, "/coffres/"+hers+"/secret?name=mot_de_passe_mqtt")

	h.signInAs(t, "cyril")
	page := body(t, h.get(t, "/coffres/"+mine.ID+"/secret?name=mot_de_passe_mqtt"))
	if strings.Contains(page, "alice") {
		t.Fatal("les lectures d'un autre coffre apparaissent sur ce secret")
	}
}

// Seeing who opened a secret says who has access to it, which is what the
// members page shows and what a reader is not shown.
func TestOnlyAManagerSeesWhoOpenedIt(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	h.writeVersions(t, vault.ID, "mot_de_passe_mqtt", "s3cr3t")

	for _, role := range []store.Role{store.RoleReader, store.RoleWriter} {
		u := h.addUser(t, "temoin"+string(role))
		if err := h.manager.DB().SetVaultMember(t.Context(), vault.ID, u.ID, role, "cyril"); err != nil {
			t.Fatalf("SetVaultMember: %v", err)
		}
		h.signInAs(t, "temoin"+string(role))

		page := body(t, h.get(t, "/coffres/"+vault.ID+"/secret?name=mot_de_passe_mqtt"))
		if strings.Contains(page, "Qui l'a ouvert") {
			t.Errorf("%s voit la liste des consultations", role)
		}
	}
}

// A refusal is the line worth reading on that page, so it is kept rather than
// filtered out with the successful reads.
func TestARefusedAttemptShowsUp(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	h.writeVersions(t, vault.ID, "mot_de_passe_mqtt", "s3cr3t")

	if err := h.manager.DB().AppendAudit(t.Context(), store.AuditEntry{
		ActorKind: store.ActorToken, ActorID: "tok", ActorLabel: "domotique",
		Action: "access.denied", Target: "mot_de_passe_mqtt", ProjectID: vault.ID,
		IP: "192.168.1.44", Detail: "adresse non autorisée pour ce secret",
	}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	page := body(t, h.get(t, "/coffres/"+vault.ID+"/secret?name=mot_de_passe_mqtt"))
	for _, want := range []string{"domotique", "refusé", "192.168.1.44", "appareil"} {
		if !strings.Contains(page, want) {
			t.Errorf("le refus n'est pas montré : %q manque", want)
		}
	}
}
