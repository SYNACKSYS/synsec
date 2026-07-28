package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"synsec/internal/store"
)

// writeVersions stores a secret several times and returns its location.
func (h *harness) writeVersions(t *testing.T, vaultID string, name string, values ...string) store.SecretLocation {
	t.Helper()
	ctx := context.Background()
	loc := store.SecretLocation{ProjectID: vaultID, Env: store.DefaultEnvironment, Name: name}

	for _, v := range values {
		if _, err := h.manager.PutSecret(ctx, loc, []byte(v), "", "cyril"); err != nil {
			t.Fatalf("PutSecret %q: %v", v, err)
		}
	}
	return loc
}

// The interface promises, at every save, that the previous value stays in the
// history. Until now nobody could see it.
func TestHistoryIsVisibleOnTheSecretPage(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	h.writeVersions(t, vault.ID, "mqtt_password", "valeurUNE", "valeurDEUX", "valeurTROIS")

	page := body(t, h.get(t, "/coffres/"+vault.ID+"/secret?name=mqtt_password"))
	for _, want := range []string{"Historique", "v1", "v2", "v3", "en cours"} {
		if !strings.Contains(page, want) {
			t.Errorf("the history does not show %q", want)
		}
	}

	// Only the current value is on the page. Listing the past must not mean
	// decrypting it, so the earlier values appear nowhere.
	if !strings.Contains(page, "valeurTROIS") {
		t.Error("the current value is missing")
	}
	for _, old := range []string{"valeurUNE", "valeurDEUX"} {
		if strings.Contains(page, old) {
			t.Errorf("the old value %q was rendered alongside the history", old)
		}
	}
}

func TestRevertBringsBackAnOldValue(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	loc := h.writeVersions(t, vault.ID, "mqtt_password", "ancien", "nouveau")
	ctx := context.Background()

	resp := h.post(t, "/coffres/"+vault.ID+"/secret/revenir", url.Values{
		"csrf": {h.csrf(t)}, "name": {"mqtt_password"}, "version": {"1"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("reverting returned %d", resp.StatusCode)
	}

	value, err := h.manager.GetSecret(ctx, loc)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(value) != "ancien" {
		t.Fatalf("the current value is %q, want the reverted one", value)
	}

	// Nothing is rewritten: the old value comes back as a new version, so the
	// log still shows what happened and when.
	meta, err := h.manager.DB().SecretMeta(ctx, loc)
	if err != nil {
		t.Fatalf("SecretMeta: %v", err)
	}
	if meta.CurrentVersion != 3 {
		t.Fatalf("the secret is at version %d, want 3 - the history was rewritten", meta.CurrentVersion)
	}

	entries, _ := h.manager.DB().ListAudit(ctx, store.AuditFilter{Action: "secret.revert"})
	if len(entries) != 1 {
		t.Fatalf("the revert was recorded %d times", len(entries))
	}
}

// Reverting is a write, so a reader must not be offered it nor allowed it.
func TestReaderCannotRevert(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	h.writeVersions(t, vault.ID, "mqtt_password", "valeurUNE", "valeurDEUX")
	alice := h.addUser(t, "alice")
	ctx := context.Background()

	if err := h.manager.DB().SetVaultMember(ctx, vault.ID, alice.ID, store.RoleReader, "cyril"); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}
	h.signInAs(t, "alice")

	page := body(t, h.get(t, "/coffres/"+vault.ID+"/secret?name=mqtt_password"))
	if !strings.Contains(page, "Historique") {
		t.Fatal("a reader cannot see the history at all")
	}
	if strings.Contains(page, "/secret/revenir") {
		t.Fatal("the revert form is offered to a reader")
	}

	resp := h.post(t, "/coffres/"+vault.ID+"/secret/revenir", url.Values{
		"csrf": {h.csrf(t)}, "name": {"mqtt_password"}, "version": {"1"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a reader reverted a secret (%d)", resp.StatusCode)
	}
}

func TestRevertRefusesNonsense(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	h.writeVersions(t, vault.ID, "mqtt_password", "valeurUNE", "valeurDEUX")

	for _, version := range []string{"0", "9", "-1", "abc", "2"} {
		resp := h.post(t, "/coffres/"+vault.ID+"/secret/revenir", url.Values{
			"csrf": {h.csrf(t)}, "name": {"mqtt_password"}, "version": {version},
		})
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
			t.Errorf("version %q was accepted: %q", version, loc)
		}
	}
}

// Reading a secret and editing it used to be the same gesture: the value
// uncovered itself when the field took focus. These hold the two apart.

func TestASecretOffersCopyAndReveal(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	h.writeVersions(t, vault.ID, "mot_de_passe_mqtt", "s3cr3t")

	page := body(t, h.get(t, "/coffres/"+vault.ID+"/secret?name=mot_de_passe_mqtt"))

	for _, want := range []string{`data-secret-field`, `data-copy="#value"`, `data-reveal="#value"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the secret page carries no %s", want)
		}
	}
	// Still covered when it arrives, whatever the buttons do afterwards.
	if !strings.Contains(page, `class="masked"`) {
		t.Error("the value arrives uncovered")
	}
}

// A new secret has nothing to uncover, so the controls must not appear.
func TestANewSecretHasNoRevealControls(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	page := body(t, h.get(t, "/coffres/"+vault.ID+"/secret"))
	if strings.Contains(page, "data-secret-field") {
		t.Error("an empty form offers to uncover a value that does not exist")
	}
}

// The controls only work with scripting, so they arrive hidden. A button that
// cannot do anything is worse than no button.
func TestScriptedControlsArriveHidden(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	h.writeVersions(t, vault.ID, "mot_de_passe_mqtt", "s3cr3t")

	page := body(t, h.get(t, "/coffres/"+vault.ID+"/secret?name=mot_de_passe_mqtt"))
	if !strings.Contains(page, "data-secret-actions hidden") {
		t.Error("the value controls are not hidden before the script runs")
	}
}
