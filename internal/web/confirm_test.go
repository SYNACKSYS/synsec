package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A session is a convenience, not a proof of presence. These hold the line
// between reading through an open tab and destroying something with it - which
// is exactly the line a crawler handed an account walked over.

func TestAnIrreversibleActionAsksForThePasswordAgain(t *testing.T) {
	h := newHarness(t)
	h.signInRaw(t)
	vault := h.newVault(t, "Maison")
	h.writeVersions(t, vault.ID, "mot_de_passe_mqtt", "s3cr3t")

	actions := map[string]url.Values{
		"/coffres/" + vault.ID + "/supprimer":        {"confirm": {vault.ID}},
		"/coffres/" + vault.ID + "/secret/supprimer": {"name": {"mot_de_passe_mqtt"}},
		"/comptes/supprimer":                         {"user": {"peu importe"}},
		"/comptes/motdepasse":                        {"user": {"peu importe"}, "password": {"nouveaumotdepasse"}},
	}

	for path, form := range actions {
		form.Set("csrf", h.csrf(t))
		resp := h.post(t, path, form)
		loc := resp.Header.Get("Location")
		if !strings.HasPrefix(loc, "/confirmer") {
			t.Errorf("%s est passée sans confirmation (%d, %q)", path, resp.StatusCode, loc)
		}
	}

	// And nothing happened while the password was being asked for.
	if _, err := h.manager.DB().Project(context.Background(), vault.ID); err != nil {
		t.Fatal("le coffre a été supprimé avant toute confirmation")
	}
}

// Reading and writing are not held: asking on every click trains people to
// type their password without reading it.
func TestOrdinaryActionsAreNotHeld(t *testing.T) {
	h := newHarness(t)
	h.signInRaw(t)
	vault := h.newVault(t, "Maison")

	resp := h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "label": {"Mot de passe MQTT"},
		"name": {"mot_de_passe_mqtt"}, "value": {"s3cr3t"},
	})
	if loc := resp.Header.Get("Location"); strings.HasPrefix(loc, "/confirmer") {
		t.Fatal("écrire un secret a demandé une confirmation")
	}
}

func TestAWrongPasswordDoesNotConfirm(t *testing.T) {
	h := newHarness(t)
	h.signInRaw(t)
	vault := h.newVault(t, "Maison")

	resp := h.post(t, "/confirmer", url.Values{
		"csrf": {h.csrf(t)}, "password": {"pas le bon"}, "retour": {"/"},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("un mot de passe incorrect a confirmé : %s", loc)
	}

	resp = h.post(t, "/coffres/"+vault.ID+"/supprimer", url.Values{
		"csrf": {h.csrf(t)}, "confirm": {vault.ID},
	})
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/confirmer") {
		t.Fatalf("la suppression est passée : %s", loc)
	}
}

// One confirmation covers a few minutes, so cleaning up several vaults does
// not mean typing the password once per vault.
func TestOneConfirmationCoversTheNextActions(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	first := h.newVault(t, "Maison")
	second := h.newVault(t, "Sauvegardes")

	for _, v := range []string{first.ID, second.ID} {
		h.post(t, "/coffres/"+v+"/supprimer", url.Values{
			"csrf": {h.csrf(t)}, "confirm": {v},
		})
		if _, err := h.manager.DB().Project(context.Background(), v); err == nil {
			t.Fatalf("le coffre %s a survécu", v)
		}
	}
}

// Signing out must not leave a confirmation standing for whoever signs in next
// on the same machine.
func TestSigningOutDropsTheConfirmation(t *testing.T) {
	h := newHarness(t)
	h.signInRaw(t)
	vault := h.newVault(t, "Maison")
	h.confirm(t)

	// The next session is a fresh one, and must prove itself on its own.
	h.post(t, "/logout", url.Values{"csrf": {h.csrf(t)}})
	h.signInRaw(t)

	resp := h.post(t, "/coffres/"+vault.ID+"/supprimer", url.Values{
		"csrf": {h.csrf(t)}, "confirm": {vault.ID},
	})
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/confirmer") {
		t.Fatalf("la confirmation a survécu à la déconnexion : %s", loc)
	}
}

// The page comes back to where the action was attempted, and only ever to a
// page of this server.
func TestTheReturnAddressStaysOnThisSite(t *testing.T) {
	for given, want := range map[string]string{
		"/coffres/abc":              "/coffres/abc",
		"//ailleurs.example/":       "/",
		"https://ailleurs.example/": "/",
		"":                          "/",
		"ailleurs.example":          "/",
	} {
		if got := safeReturn(given); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", given, got, want)
		}
	}
}

func TestConfirmationIsRefusedWithoutASession(t *testing.T) {
	h := newHarness(t)
	resp := h.post(t, "/confirmer", url.Values{"password": {testPassword}})
	if resp.StatusCode != http.StatusSeeOther ||
		!strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("la page de confirmation a répondu %d à un anonyme", resp.StatusCode)
	}
}

// The confirmation page is reachable by whoever already holds a session, so an
// open tab must not become a password oracle. It is throttled like the sign-in
// form.
func TestConfirmationIsThrottled(t *testing.T) {
	h := newHarness(t)
	h.signInRaw(t)

	var last string
	for i := 0; i < throttleAfter+1; i++ {
		resp := h.post(t, "/confirmer", url.Values{
			"csrf": {h.csrf(t)}, "password": {"pas le bon"}, "retour": {"/"},
		})
		last = resp.Header.Get("Location")
	}
	if !strings.Contains(last, "Trop+de+tentatives") {
		t.Fatalf("aucun freinage après %d essais : %s", throttleAfter+1, last)
	}

	// And the lockout holds even once the password is right.
	resp := h.post(t, "/confirmer", url.Values{
		"csrf": {h.csrf(t)}, "password": {testPassword}, "retour": {"/"},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "Trop+de+tentatives") {
		t.Fatalf("le bon mot de passe a contourné le verrou : %s", loc)
	}
}
