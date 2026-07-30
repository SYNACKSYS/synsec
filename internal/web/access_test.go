package web

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"synsec/internal/auth"
	"synsec/internal/crypto"
	"synsec/internal/store"
)

var lightArgon2 = crypto.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}

// addUser creates an ordinary, non-administrator account.
func (h *harness) addUser(t *testing.T, username string) store.User {
	t.Helper()

	cred, err := auth.HashPasswordWith(testPassword, lightArgon2)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	u := store.User{Username: username, DisplayName: username, IsAdmin: false}
	if err := h.manager.DB().CreateUser(context.Background(), &u, cred); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

// signInAs replaces the harness's cookie jar and signs in as someone else, so
// a test can look at the interface through their eyes.
// newJar gives the harness a fresh browser, with no cookies at all.
func (h *harness) newJar(t *testing.T) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	h.client.Jar = jar
}

func (h *harness) signInAs(t *testing.T, username string) {
	t.Helper()
	h.newJar(t)

	resp := h.post(t, "/login", url.Values{
		"login_csrf": {h.loginToken(t)},
		"username":   {username},
		"password":   {testPassword},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("signing in as %s returned %d", username, resp.StatusCode)
	}
	h.confirm(t)
}

// A vault nobody granted must be absent from the list, not merely read-only.
func TestStrangerSeesNoVaults(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	h.addUser(t, "alice")

	h.signInAs(t, "alice")
	page := body(t, h.get(t, "/"))
	// The link is what makes this unambiguous: the interface's own empty-state
	// copy uses "Maison" as an example, so looking for the name alone would
	// match the placeholder text rather than a real vault.
	if strings.Contains(page, "/coffres/"+vault.ID) {
		t.Fatal("a stranger sees a vault they hold no role on")
	}

	// And the vault itself must answer 404 rather than 403: a 403 would
	// confirm that something exists behind that identifier.
	resp := h.get(t, "/coffres/"+vault.ID)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a stranger got %d on a vault, want 404", resp.StatusCode)
	}
}

func TestReaderSeesButCannotWrite(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")

	ctx := context.Background()
	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	if _, err := h.manager.PutSecret(ctx, loc, []byte("s3cr3t"), "", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	if err := h.manager.DB().SetVaultMember(ctx, vault.ID, alice.ID, store.RoleReader, "cyril"); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}

	h.signInAs(t, "alice")

	if page := body(t, h.get(t, "/")); !strings.Contains(page, "/coffres/"+vault.ID) {
		t.Fatal("a reader does not see the vault they were granted")
	}
	if resp := h.get(t, "/coffres/"+vault.ID); resp.StatusCode != http.StatusOK {
		t.Fatalf("a reader got %d on the vault", resp.StatusCode)
	}
	if page := body(t, h.get(t, "/coffres/"+vault.ID+"/secret?name=mqtt_password")); !strings.Contains(page, "s3cr3t") {
		t.Fatal("a reader cannot see the value they were granted")
	}

	// Writing must be refused, and refused the same way as an absent vault.
	resp := h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "editing": {"1"}, "name": {"mqtt_password"}, "value": {"remplacé"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a reader's write returned %d, want 404", resp.StatusCode)
	}

	value, err := h.manager.GetSecret(ctx, loc)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(value) != "s3cr3t" {
		t.Fatalf("a reader changed the value to %q", value)
	}
}

func TestWriterCanWrite(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")

	ctx := context.Background()
	if err := h.manager.DB().SetVaultMember(ctx, vault.ID, alice.ID, store.RoleWriter, "cyril"); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}

	h.signInAs(t, "alice")
	resp := h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "name": {"mqtt_password"}, "value": {"s3cr3t"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a writer's write returned %d", resp.StatusCode)
	}
}

// The point of an individual share: one secret, without the rest of the vault.
func TestSharedSecretIsReachableWithoutTheVault(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")
	ctx := context.Background()

	shared := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	other := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "zigbee_cle"}
	if _, err := h.manager.PutSecret(ctx, shared, []byte("partagé"), "", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	if _, err := h.manager.PutSecret(ctx, other, []byte("privé"), "", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	meta, err := h.manager.DB().SecretMeta(ctx, shared)
	if err != nil {
		t.Fatalf("SecretMeta: %v", err)
	}
	if err := h.manager.DB().SetSecretShare(ctx, meta.ID, alice.ID, store.RoleReader, "cyril"); err != nil {
		t.Fatalf("SetSecretShare: %v", err)
	}

	h.signInAs(t, "alice")

	// It appears on her home page, named with the vault she cannot open.
	page := body(t, h.get(t, "/"))
	if !strings.Contains(page, "mqtt_password") {
		t.Fatal("the shared secret is absent from the recipient's home page")
	}
	if !strings.Contains(page, "Secrets partagés avec moi") {
		t.Fatal("the shared section is missing")
	}

	// She can open it.
	if page := body(t, h.get(t, "/coffres/"+vault.ID+"/secret?name=mqtt_password")); !strings.Contains(page, "partagé") {
		t.Fatal("the recipient cannot read the secret shared with them")
	}

	// But nothing else in that vault, and not the vault itself.
	if resp := h.get(t, "/coffres/"+vault.ID); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("the recipient reached the vault (%d)", resp.StatusCode)
	}
	if resp := h.get(t, "/coffres/"+vault.ID+"/secret?name=zigbee_cle"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("the recipient reached another secret (%d)", resp.StatusCode)
	}
}

// Someone who holds only a share must never be offered a way into the vault
// around it: every link out of the page would land on "does not exist".
func TestSharedSecretPageNeverLinksToTheVault(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")
	ctx := context.Background()

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	if _, err := h.manager.PutSecret(ctx, loc, []byte("s3cr3t"), "", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	meta, _ := h.manager.DB().SecretMeta(ctx, loc)
	h.manager.DB().SetSecretShare(ctx, meta.ID, alice.ID, store.RoleWriter, "cyril")

	h.signInAs(t, "alice")
	page := body(t, h.get(t, "/coffres/"+vault.ID+"/secret?name=mqtt_password"))

	if strings.Contains(page, `href="/coffres/`+vault.ID+`"`) {
		t.Fatal("the page links to a vault the reader cannot open")
	}
	// The cancel button specifically, not just any link to the home page -
	// the breadcrumb always has one.
	if !strings.Contains(page, `class="btn btn-ghost" href="/"`) {
		t.Fatal("the cancel button does not lead back to the home page")
	}

	// And saving must not drop them on that vault either.
	resp := h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "editing": {"1"}, "name": {"mqtt_password"}, "value": {"remplacé"},
	})
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Fatalf("saving redirected to %q, want the home page", loc)
	}

	// A vault member, by contrast, goes back to the vault.
	h.signInAs(t, "cyril")
	resp = h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "editing": {"1"}, "name": {"mqtt_password"}, "value": {"encore"},
	})
	if loc := resp.Header.Get("Location"); loc != "/coffres/"+vault.ID {
		t.Fatalf("a member's save redirected to %q", loc)
	}
}

func TestSharedReaderCannotWriteButSharedWriterCan(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")
	ctx := context.Background()

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	if _, err := h.manager.PutSecret(ctx, loc, []byte("s3cr3t"), "", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	meta, _ := h.manager.DB().SecretMeta(ctx, loc)

	h.manager.DB().SetSecretShare(ctx, meta.ID, alice.ID, store.RoleReader, "cyril")
	h.signInAs(t, "alice")

	resp := h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "editing": {"1"}, "name": {"mqtt_password"}, "value": {"remplacé"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a read-only share allowed a write (%d)", resp.StatusCode)
	}

	// Raised to writer, the same request must go through.
	h.manager.DB().SetSecretShare(ctx, meta.ID, alice.ID, store.RoleWriter, "cyril")
	h.signInAs(t, "alice")

	resp = h.post(t, "/coffres/"+vault.ID+"/secret", url.Values{
		"csrf": {h.csrf(t)}, "editing": {"1"}, "name": {"mqtt_password"}, "value": {"remplacé"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a write share was refused (%d)", resp.StatusCode)
	}
	value, _ := h.manager.GetSecret(ctx, loc)
	if string(value) != "remplacé" {
		t.Fatalf("the value is %q after a shared write", value)
	}
}

// Destroying a secret with all its history stays a vault right: someone handed
// one password must not be able to erase it on its owner's behalf.
func TestSharedWriterCannotDelete(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")
	ctx := context.Background()

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	h.manager.PutSecret(ctx, loc, []byte("s3cr3t"), "", "cyril")
	meta, _ := h.manager.DB().SecretMeta(ctx, loc)
	h.manager.DB().SetSecretShare(ctx, meta.ID, alice.ID, store.RoleWriter, "cyril")

	h.signInAs(t, "alice")
	resp := h.post(t, "/coffres/"+vault.ID+"/secret/supprimer", url.Values{
		"csrf": {h.csrf(t)}, "name": {"mqtt_password"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a share allowed a deletion (%d)", resp.StatusCode)
	}

	if _, err := h.manager.GetSecret(ctx, loc); err != nil {
		t.Fatalf("the secret was deleted anyway: %v", err)
	}
}

// Creating a vault has to grant its creator access, or they could not open
// what they just made.
func TestCreatorBecomesManager(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "alice")
	h.signInAs(t, "alice")

	resp := h.post(t, "/coffres", url.Values{
		"csrf": {h.csrf(t)}, "name": {"Perso"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("creating a vault returned %d", resp.StatusCode)
	}

	if resp := h.get(t, resp.Header.Get("Location")); resp.StatusCode != http.StatusOK {
		t.Fatalf("the creator cannot open their own vault (%d)", resp.StatusCode)
	}
}

// The home page separates vaults by owner, not by role: a vault someone else
// created stays theirs even when you have been made its manager.
func TestSharedVaultStaysUnderItsOwner(t *testing.T) {
	h := newHarness(t)
	alice := h.addUser(t, "alice")
	h.signInAs(t, "alice")

	resp := h.post(t, "/coffres", url.Values{"csrf": {h.csrf(t)}, "name": {"Perso"}})
	vaultID := strings.TrimPrefix(resp.Header.Get("Location"), "/coffres/")

	// Cyril is made manager - the strongest role there is.
	ctx := context.Background()
	admin, err := h.manager.DB().UserByUsername(ctx, "cyril")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	if err := h.manager.DB().SetVaultMember(ctx, vaultID, admin.ID, store.RoleManager, alice.Username); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}

	h.signInAs(t, "cyril")
	page := body(t, h.get(t, "/"))

	shared := strings.Index(page, "Coffres partagés avec moi")
	if shared < 0 {
		t.Fatal("the shared vaults section is missing")
	}
	if at := strings.Index(page, "/coffres/"+vaultID); at < shared {
		t.Fatal("a vault owned by someone else is listed among one's own")
	}
	if !strings.Contains(page, "de alice") {
		t.Fatal("the shared vault does not say whose it is")
	}
}

// Administering the server and reading other people's secrets are separate
// things. An administrator creates accounts and runs the service; a vault
// nobody shared with them stays invisible, exactly as for anyone else.
func TestAdministratorSeesOnlyWhatIsSharedWithThem(t *testing.T) {
	h := newHarness(t)
	alice := h.addUser(t, "alice")
	h.signInAs(t, "alice")

	resp := h.post(t, "/coffres", url.Values{"csrf": {h.csrf(t)}, "name": {"Perso"}})
	vaultURL := resp.Header.Get("Location")
	vaultID := strings.TrimPrefix(vaultURL, "/coffres/")

	h.signInAs(t, "cyril") // the administrator created by the harness
	if page := body(t, h.get(t, "/")); strings.Contains(page, vaultURL) {
		t.Fatal("an administrator sees a vault nobody shared with them")
	}
	if resp := h.get(t, vaultURL); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an administrator got %d on someone else's vault, want 404", resp.StatusCode)
	}

	// Granted like anyone else, they see it.
	admin, err := h.manager.DB().UserByUsername(context.Background(), "cyril")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	if err := h.manager.DB().SetVaultMember(context.Background(), vaultID, admin.ID, store.RoleReader, alice.Username); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}
	if resp := h.get(t, vaultURL); resp.StatusCode != http.StatusOK {
		t.Fatalf("an administrator granted read access got %d", resp.StatusCode)
	}
}
