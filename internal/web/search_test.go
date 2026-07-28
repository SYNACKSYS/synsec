package web

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"synsec/internal/store"
)

// newVaultOwnedBy creates a vault belonging to someone other than the first
// account. The shared helper always names cyril as owner, which would make an
// isolation test pass for the wrong reason.
func (h *harness) newVaultOwnedBy(t *testing.T, username, name string) store.Project {
	t.Helper()
	ctx := context.Background()

	owner, err := h.manager.DB().UserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	p, err := h.manager.CreateVault(ctx, name, "", owner.ID)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if err := h.manager.DB().SetVaultMember(ctx, p.ID, owner.ID, store.RoleManager, "test"); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}
	return p
}

// Search walks the same two calls the front page uses, so it inherits the same
// access control. These hold that inheritance to its promise: what matters is
// not that the right things are found but that the wrong ones are not.

func TestSearchFindsASecretAcrossVaults(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	maison := h.newVault(t, "Maison")
	h.writeVersions(t, maison.ID, "mot_de_passe_mqtt", "s3cr3t")
	sauvegardes := h.newVault(t, "Sauvegardes")
	h.writeVersions(t, sauvegardes.ID, "cle_disque_externe", "s3cr3t")

	page := body(t, h.get(t, "/recherche?q=mqtt"))
	if !strings.Contains(page, "mot_de_passe_mqtt") {
		t.Fatal("the secret was not found")
	}
	if !strings.Contains(page, "Maison") {
		t.Fatal("the result does not say which vault it lives in")
	}
	if strings.Contains(page, "cle_disque_externe") {
		t.Fatal("a secret that does not match was returned")
	}
}

// The whole point of the page: a name is enough, the vault need not be known.
func TestSearchNeverLeavesTheVaultsYouCanReach(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	mine := h.newVault(t, "Maison")
	h.writeVersions(t, mine.ID, "mot_de_passe_mqtt", "s3cr3t")

	// Alice has a vault of her own with a name that would match.
	h.addUser(t, "alice")
	h.signInAs(t, "alice")
	hers := h.newVaultOwnedBy(t, "alice", "Chez Alice")
	h.writeVersions(t, hers.ID, "mqtt_alice", "s3cr3t")

	page := body(t, h.get(t, "/recherche?q=mqtt"))
	if !strings.Contains(page, "mqtt_alice") {
		t.Fatal("Alice cannot find her own secret")
	}
	if strings.Contains(page, "mot_de_passe_mqtt") || strings.Contains(page, "Maison") {
		t.Fatal("the search reached a vault that was never shared")
	}
}

// A value must never be searchable, or the page would decrypt every secret in
// every vault on each query - the wholesale read the journal exists to expose.
func TestSearchDoesNotReachValues(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	vault := h.newVault(t, "Maison")
	h.writeVersions(t, vault.ID, "mot_de_passe_mqtt", "brouette-magenta")

	page := body(t, h.get(t, "/recherche?q=brouette"))
	if strings.Contains(page, "mot_de_passe_mqtt") {
		t.Fatal("a secret was found by its value")
	}
	if strings.Contains(page, "brouette-magenta") {
		t.Fatal("a value appeared on the search page")
	}
}

// Accents are typed or not depending on the keyboard and the hurry.
func TestSearchIgnoresAccentsAndCase(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	vault := h.newVault(t, "Maison")
	h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "label": {"Clé du régulateur"},
		"name": {"cle_regulateur"}, "value": {"s3cr3t"},
	})

	for _, query := range []string{"régulateur", "regulateur", "RÉGULATEUR", "Clé"} {
		page := body(t, h.get(t, "/recherche?q="+url.QueryEscape(query)))
		if !strings.Contains(page, "cle_regulateur") {
			t.Errorf("%q found nothing", query)
		}
	}
}

// An empty query is not a search for everything.
func TestAnEmptySearchListsNothing(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	h.writeVersions(t, vault.ID, "mot_de_passe_mqtt", "s3cr3t")

	page := body(t, h.get(t, "/recherche"))
	if strings.Contains(page, "mot_de_passe_mqtt") {
		t.Fatal("an empty query listed the secrets")
	}
}

func TestFoldRemovesAccents(t *testing.T) {
	cases := map[string]string{
		"Clé":          "cle",
		"RÉGULATEUR":   "regulateur",
		"Noël":         "noel",
		"français":     "francais",
		"cœur":         "coeur",
		"mot_de_passe": "mot_de_passe",
	}
	for in, want := range cases {
		if got := fold(in); got != want {
			t.Errorf("fold(%q) = %q, want %q", in, got, want)
		}
	}
}
