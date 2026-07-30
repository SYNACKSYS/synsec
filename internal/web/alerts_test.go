package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"synsec/internal/alert"
)

// The alerts page says what happens in every vault, and holds the address it
// says it to. Same door as the journal.
func TestOnlyTheRootAccountConfiguresTheAlerts(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	h.addAdmin(t, "admin")
	h.signInAs(t, "admin")

	if code := h.get(t, "/parametres/alertes").StatusCode; code != http.StatusNotFound {
		t.Errorf("un administrateur ordinaire atteint la page des alertes (%d)", code)
	}
	resp := h.post(t, "/parametres/alertes", url.Values{
		"csrf": {h.csrf(t)}, "url": {"https://ailleurs.example/hook"}, "enabled": {"1"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("un administrateur ordinaire a pu écrire l'adresse (%d)", resp.StatusCode)
	}
}

// Saving an address makes a signing key, so the receiving end has something to
// check with. Nobody has to think of one.
func TestSavingAnAddressMintsASigningKey(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	h.post(t, "/parametres/alertes", url.Values{
		"csrf": {h.csrf(t)}, "url": {"https://domotique.maison:8123/api/webhook/synsec"},
		"level": {"critique"}, "enabled": {"1"},
	})

	secret, err := h.manager.SealedSetting(t.Context(), alert.SettingSecret, "")
	if err != nil {
		t.Fatalf("SealedSetting: %v", err)
	}
	if len(secret) < 32 {
		t.Fatalf("clé de signature absente ou trop courte : %q", secret)
	}

	page := body(t, h.get(t, "/parametres/alertes"))
	if !strings.Contains(page, secret) {
		t.Error("la page ne montre pas la clé, impossible de configurer le destinataire")
	}
	if !strings.Contains(page, "domotique.maison") {
		t.Error("la page ne montre pas l'adresse enregistrée")
	}
}

// Armed with nowhere to send is the state where somebody believes they are
// watched over and are not.
func TestAlertsCannotBeArmedWithoutAnAddress(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	resp := h.post(t, "/parametres/alertes", url.Values{
		"csrf": {h.csrf(t)}, "url": {""}, "enabled": {"1"},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("les alertes ont été activées sans destination : %s", loc)
	}
	enabled, err := h.manager.DB().ServerSetting(t.Context(), alert.SettingEnabled, "")
	if err != nil {
		t.Fatalf("ServerSetting: %v", err)
	}
	if enabled == "1" {
		t.Fatal("les alertes sont marquées actives sans adresse")
	}
}

// An address SYNSEC cannot post to is refused while somebody is looking at the
// form, not at three in the morning when the message does not arrive.
func TestAnImpossibleAddressIsRefused(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	resp := h.post(t, "/parametres/alertes", url.Values{
		"csrf": {h.csrf(t)}, "url": {"ftp://ailleurs.example/hook"}, "enabled": {"1"},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("une adresse en ftp a été acceptée : %s", loc)
	}
}

// The address is a credential more often than not - a Discord or ntfy URL is a
// bearer token with a hostname in front - so it does not sit in the clear.
func TestTheAddressIsStoredSealed(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	const address = "https://discord.example/api/webhooks/12345/tres-secret"
	h.post(t, "/parametres/alertes", url.Values{
		"csrf": {h.csrf(t)}, "url": {address}, "level": {"critique"},
	})

	stored, err := h.manager.DB().ServerSetting(t.Context(), alert.SettingURL, "")
	if err != nil {
		t.Fatalf("ServerSetting: %v", err)
	}
	if stored == "" {
		t.Fatal("rien n'a été enregistré")
	}
	if strings.Contains(stored, "tres-secret") || stored == address {
		t.Fatalf("l'adresse est stockée en clair : %s", stored)
	}

	// And it comes back intact through the root key.
	back, err := h.manager.SealedSetting(t.Context(), alert.SettingURL, "")
	if err != nil {
		t.Fatalf("SealedSetting: %v", err)
	}
	if back != address {
		t.Fatalf("relue : %q", back)
	}
}
