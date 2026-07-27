package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"synsec/internal/auth"
	"synsec/internal/store"
)

// addAdmin creates a second administrator, who holds the flag but not the
// journal.
func (h *harness) addAdmin(t *testing.T, username string) store.User {
	t.Helper()

	cred, err := auth.HashPasswordWith(testPassword, lightArgon2)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	u := store.User{Username: username, DisplayName: username, IsAdmin: true}
	if err := h.manager.DB().CreateUser(context.Background(), &u, cred); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

// The journal spans every vault. Holding the administrator flag is not enough
// to read it, and someone refused must not even learn the page exists.
func TestJournalIsClosedToOtherAdmins(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	h.addAdmin(t, "alice")

	if resp := h.get(t, "/journal"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the root account cannot read the journal (%d)", resp.StatusCode)
	}

	h.signInAs(t, "alice")
	if resp := h.get(t, "/journal"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("another administrator read the journal (%d)", resp.StatusCode)
	}
	if page := body(t, h.get(t, "/")); strings.Contains(page, "/journal") {
		t.Fatal("the sidebar advertises the journal to someone refused it")
	}
}

func TestRootGrantsAndRevokesJournalAccess(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	alice := h.addAdmin(t, "alice")

	resp := h.post(t, "/journal/acces", url.Values{
		"csrf": {h.csrf(t)}, "user": {alice.ID},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("granting returned %d", resp.StatusCode)
	}

	h.signInAs(t, "alice")
	if resp := h.get(t, "/journal"); resp.StatusCode != http.StatusOK {
		t.Fatalf("alice was granted the journal but cannot read it (%d)", resp.StatusCode)
	}
	// The grant reads the journal; it does not hand out the journal.
	if resp := h.get(t, "/journal/acces"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a granted administrator reached the access page (%d)", resp.StatusCode)
	}

	h.signInAs(t, "cyril")
	h.post(t, "/journal/acces/retirer", url.Values{
		"csrf": {h.csrf(t)}, "user": {alice.ID},
	})

	h.signInAs(t, "alice")
	if resp := h.get(t, "/journal"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("alice still reads the journal after the grant was withdrawn (%d)", resp.StatusCode)
	}
}

// A grant accompanies the administrator flag. Someone who never had it, or who
// lost it, does not read the journal whatever the grants table says.
func TestJournalGrantNeedsTheAdminFlag(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	bob := h.addUser(t, "bob")

	resp := h.post(t, "/journal/acces", url.Values{
		"csrf": {h.csrf(t)}, "user": {bob.ID},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("the journal was opened to a non-administrator: %q", loc)
	}

	// Even with the row forced in, the flag still decides.
	if err := h.manager.DB().GrantAuditReader(context.Background(), bob.ID, "test"); err != nil {
		t.Fatalf("GrantAuditReader: %v", err)
	}
	h.signInAs(t, "bob")
	if resp := h.get(t, "/journal"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a granted non-administrator read the journal (%d)", resp.StatusCode)
	}
}

func TestJournalFilters(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	if _, err := h.manager.PutSecret(ctx, loc, []byte("s3cr3t"), "", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	h.get(t, "/coffres/"+vault.ID+"/secret?name=mqtt_password") // records secret.read

	page := body(t, h.get(t, "/journal"))
	if !strings.Contains(page, "mqtt_password") {
		t.Fatal("the journal does not show the secret that was opened")
	}
	if strings.Contains(page, "s3cr3t") {
		t.Fatal("the journal shows a secret value")
	}

	// A search that matches nothing must empty the table rather than ignore it.
	if page := body(t, h.get(t, "/journal?q=zzzzz")); strings.Contains(page, "mqtt_password") {
		t.Fatal("the search filter was ignored")
	}

	// A term full of wildcards is looked for literally.
	if page := body(t, h.get(t, "/journal?q=%25")); strings.Contains(page, "mqtt_password") {
		t.Fatal("a percent sign in the search matched everything")
	}
}

// The account the server was set up with cannot be deleted: it is the only one
// that can ever hand out the journal.
func TestRootAccountCannotBeDeleted(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	h.addAdmin(t, "alice")
	ctx := context.Background()

	cyril, err := h.manager.DB().UserByUsername(ctx, "cyril")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}

	h.signInAs(t, "alice")
	resp := h.post(t, "/comptes/supprimer", url.Values{
		"csrf": {h.csrf(t)}, "user": {cyril.ID},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("the root account was deleted: %q", loc)
	}

	if _, err := h.manager.DB().User(ctx, cyril.ID); err != nil {
		t.Fatalf("the root account is gone: %v", err)
	}
}
