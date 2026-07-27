package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"synsec/internal/store"
)

func TestMembersPageIsManagerOnly(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")
	ctx := context.Background()

	// A writer may change secrets but not who reaches them.
	if err := h.manager.DB().SetVaultMember(ctx, vault.ID, alice.ID, store.RoleWriter, "cyril"); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}
	h.signInAs(t, "alice")

	if resp := h.get(t, "/coffres/"+vault.ID+"/membres"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a writer reached the members page (%d)", resp.StatusCode)
	}
	resp := h.post(t, "/coffres/"+vault.ID+"/membres", url.Values{
		"csrf": {h.csrf(t)}, "user": {alice.ID}, "role": {"manager"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a writer granted themselves manager (%d)", resp.StatusCode)
	}

	role, _ := h.manager.DB().VaultRole(ctx, vault.ID, alice.ID)
	if role != store.RoleWriter {
		t.Fatalf("the role changed to %q", role)
	}
}

func TestGrantAndRevokeFromTheBrowser(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")
	ctx := context.Background()

	resp := h.post(t, "/coffres/"+vault.ID+"/membres", url.Values{
		"csrf": {h.csrf(t)}, "user": {alice.ID}, "role": {"reader"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("granting returned %d", resp.StatusCode)
	}
	if role, _ := h.manager.DB().VaultRole(ctx, vault.ID, alice.ID); role != store.RoleReader {
		t.Fatalf("the granted role is %q", role)
	}

	// The members page lists her, and no longer offers her as a candidate.
	page := body(t, h.get(t, "/coffres/"+vault.ID+"/membres"))
	if !strings.Contains(page, "alice") {
		t.Fatal("the new member is missing from the list")
	}

	resp = h.post(t, "/coffres/"+vault.ID+"/membres/retirer", url.Values{
		"csrf": {h.csrf(t)}, "user": {alice.ID},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoking returned %d", resp.StatusCode)
	}
	if role, _ := h.manager.DB().VaultRole(ctx, vault.ID, alice.ID); role != store.RoleNone {
		t.Fatalf("access survived revocation: %q", role)
	}
}

// Removing the last manager would leave the vault with nobody able to grant
// access to it again.
func TestCannotRemoveTheLastManager(t *testing.T) {
	h := newHarness(t)
	alice := h.addUser(t, "alice")
	h.signInAs(t, "alice")

	resp := h.post(t, "/coffres", url.Values{"csrf": {h.csrf(t)}, "name": {"Perso"}})
	vaultID := strings.TrimPrefix(resp.Header.Get("Location"), "/coffres/")

	resp = h.post(t, "/coffres/"+vaultID+"/membres/retirer", url.Values{
		"csrf": {h.csrf(t)}, "user": {alice.ID},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("the attempt returned %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("no explanation was given: redirected to %q", loc)
	}

	role, _ := h.manager.DB().VaultRole(context.Background(), vaultID, alice.ID)
	if role != store.RoleManager {
		t.Fatalf("the last manager was removed anyway (role is %q)", role)
	}
}

func TestShareSecretFromTheBrowser(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")
	ctx := context.Background()

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	if _, err := h.manager.PutSecret(ctx, loc, []byte("s3cr3t"), "", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	resp := h.post(t, "/coffres/"+vault.ID+"/partages", url.Values{
		"csrf": {h.csrf(t)}, "name": {"mqtt_password"},
		"user": {alice.ID}, "role": {"reader"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("sharing returned %d", resp.StatusCode)
	}

	meta, _ := h.manager.DB().SecretMeta(ctx, loc)
	if role, _ := h.manager.DB().SecretShareRole(ctx, meta.ID, alice.ID); role != store.RoleReader {
		t.Fatalf("the share role is %q", role)
	}

	// She reaches the secret and nothing else.
	h.signInAs(t, "alice")
	if page := body(t, h.get(t, "/")); !strings.Contains(page, "mqtt_password") {
		t.Fatal("the shared secret is absent from the recipient's home page")
	}
	if resp := h.get(t, "/coffres/"+vault.ID); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("the recipient reached the vault (%d)", resp.StatusCode)
	}
}

// A share is never granted at manager level: passing it on is not something a
// recipient may do, and destroying a secret is a vault right.
func TestShareRefusesManagerLevel(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")
	ctx := context.Background()

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	h.manager.PutSecret(ctx, loc, []byte("s3cr3t"), "", "cyril")

	resp := h.post(t, "/coffres/"+vault.ID+"/partages", url.Values{
		"csrf": {h.csrf(t)}, "name": {"mqtt_password"},
		"user": {alice.ID}, "role": {"manager"},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("a manager-level share was accepted: redirected to %q", loc)
	}

	meta, _ := h.manager.DB().SecretMeta(ctx, store.SecretLocation{
		ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password",
	})
	if role, _ := h.manager.DB().SecretShareRole(ctx, meta.ID, alice.ID); role != store.RoleNone {
		t.Fatalf("a share was created at %q", role)
	}
}

// Someone a secret was shared with must not be able to pass it on.
func TestRecipientCannotReshare(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")
	bob := h.addUser(t, "bob")
	ctx := context.Background()

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	h.manager.PutSecret(ctx, loc, []byte("s3cr3t"), "", "cyril")
	meta, _ := h.manager.DB().SecretMeta(ctx, loc)
	h.manager.DB().SetSecretShare(ctx, meta.ID, alice.ID, store.RoleWriter, "cyril")

	h.signInAs(t, "alice")
	resp := h.post(t, "/coffres/"+vault.ID+"/partages", url.Values{
		"csrf": {h.csrf(t)}, "name": {"mqtt_password"},
		"user": {bob.ID}, "role": {"reader"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a recipient re-shared the secret (%d)", resp.StatusCode)
	}
	if role, _ := h.manager.DB().SecretShareRole(ctx, meta.ID, bob.ID); role != store.RoleNone {
		t.Fatalf("bob ended up with %q", role)
	}
}

func TestGrantsAreAudited(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")

	h.post(t, "/coffres/"+vault.ID+"/membres", url.Values{
		"csrf": {h.csrf(t)}, "user": {alice.ID}, "role": {"reader"},
	})
	h.post(t, "/coffres/"+vault.ID+"/membres/retirer", url.Values{
		"csrf": {h.csrf(t)}, "user": {alice.ID},
	})

	entries, err := h.manager.DB().ListAudit(context.Background(), store.AuditFilter{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		seen[e.Action] = true
	}
	for _, action := range []string{"vault.grant", "vault.revoke"} {
		if !seen[action] {
			t.Fatalf("%s was not recorded; log holds %v", action, seen)
		}
	}
}
