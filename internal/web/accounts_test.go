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

func TestAccountsPageIsAdminOnly(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "alice")
	h.signInAs(t, "alice")

	// Not 403: an ordinary account should not even learn the section exists.
	if resp := h.get(t, "/comptes"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an ordinary account reached /comptes (%d)", resp.StatusCode)
	}
	resp := h.post(t, "/comptes", url.Values{
		"csrf": {h.csrf(t)}, "username": {"bob"}, "password": {testPassword},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an ordinary account created a user (%d)", resp.StatusCode)
	}

	if _, err := h.manager.DB().UserByUsername(context.Background(), "bob"); err == nil {
		t.Fatal("the account was created anyway")
	}
}

// The section is not advertised either: an ordinary account sees no link.
func TestAccountsLinkOnlyForAdministrators(t *testing.T) {
	h := newHarness(t)

	h.signIn(t)
	if page := body(t, h.get(t, "/")); !strings.Contains(page, "/comptes") {
		t.Fatal("an administrator sees no link to the accounts page")
	}

	h.addUser(t, "alice")
	h.signInAs(t, "alice")
	if page := body(t, h.get(t, "/")); strings.Contains(page, "/comptes") {
		t.Fatal("an ordinary account is shown a link to the accounts page")
	}
}

func TestCreateAccountFromTheBrowser(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	resp := h.post(t, "/comptes", url.Values{
		"csrf": {h.csrf(t)}, "username": {"alice"},
		"display_name": {"Alice"}, "password": {testPassword},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("creating an account returned %d", resp.StatusCode)
	}

	created, err := h.manager.DB().UserByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatalf("the account was not created: %v", err)
	}
	if created.DisplayName != "Alice" || created.IsAdmin {
		t.Fatalf("the account came out as %+v", created)
	}

	// And it works: the new person can sign in.
	h.signInAs(t, "alice")
}

// Creating an account must open nothing: the whole point of the model is that
// an administrator sees no more than what was shared with them.
func TestNewAccountSeesNothing(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	h.post(t, "/comptes", url.Values{
		"csrf": {h.csrf(t)}, "username": {"alice"}, "password": {testPassword},
	})

	h.signInAs(t, "alice")
	// Matched on the link rather than the name: the empty-state copy offers
	// "Maison" as an example, and would satisfy a naive search.
	if page := body(t, h.get(t, "/")); strings.Contains(page, "/coffres/"+vault.ID) {
		t.Fatal("a brand new account already sees someone else's vault")
	}
}

func TestCreateAccountRejectsWeakOrDuplicate(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	short := h.post(t, "/comptes", url.Values{
		"csrf": {h.csrf(t)}, "username": {"alice"}, "password": {"court"},
	})
	if loc := short.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("a short password was accepted: redirected to %q", loc)
	}

	h.post(t, "/comptes", url.Values{
		"csrf": {h.csrf(t)}, "username": {"alice"}, "password": {testPassword},
	})
	duplicate := h.post(t, "/comptes", url.Values{
		"csrf": {h.csrf(t)}, "username": {"ALICE"}, "password": {testPassword},
	})
	if loc := duplicate.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("a duplicate name was accepted: redirected to %q", loc)
	}
}

// A password changed because it leaked must close the sessions the leak could
// already be using.
func TestResetPasswordClosesSessions(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	alice := h.addUser(t, "alice")

	h.signInAs(t, "alice")
	if resp := h.get(t, "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("alice is not signed in (%d)", resp.StatusCode)
	}
	aliceJar := h.client.Jar

	h.signInAs(t, "cyril")
	resp := h.post(t, "/comptes/motdepasse", url.Values{
		"csrf": {h.csrf(t)}, "user": {alice.ID}, "password": {"un nouveau mot de passe"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("resetting returned %d", resp.StatusCode)
	}

	h.client.Jar = aliceJar
	if resp := h.get(t, "/"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("alice's old session still works (%d)", resp.StatusCode)
	}

	// The new password is the one that works now.
	cred, err := h.manager.DB().UserCredentials(context.Background(), alice.ID)
	if err != nil {
		t.Fatalf("UserCredentials: %v", err)
	}
	if !auth.VerifyPassword(cred, "un nouveau mot de passe") {
		t.Fatal("the new password does not verify")
	}
}

func TestCannotDeleteSelf(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	admin, err := h.manager.DB().UserByUsername(context.Background(), "cyril")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}

	resp := h.post(t, "/comptes/supprimer", url.Values{
		"csrf": {h.csrf(t)}, "user": {admin.ID},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("self-deletion was accepted: redirected to %q", loc)
	}
	if _, err := h.manager.DB().User(context.Background(), admin.ID); err != nil {
		t.Fatal("the administrator deleted themselves")
	}
}

// Removing the only manager of a vault would strand it: since an
// administrator no longer sees what was not shared with them, nobody could
// reach it again.
func TestCannotDeleteTheSoleManagerOfAVault(t *testing.T) {
	h := newHarness(t)
	alice := h.addUser(t, "alice")

	h.signInAs(t, "alice")
	h.post(t, "/coffres", url.Values{"csrf": {h.csrf(t)}, "name": {"Perso"}})

	h.signInAs(t, "cyril")
	resp := h.post(t, "/comptes/supprimer", url.Values{
		"csrf": {h.csrf(t)}, "user": {alice.ID},
	})

	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "erreur=") {
		t.Fatalf("the account was deleted: redirected to %q", loc)
	}
	if !strings.Contains(loc, "Perso") {
		t.Fatalf("the message does not name the vault in the way: %q", loc)
	}
	if _, err := h.manager.DB().User(context.Background(), alice.ID); err != nil {
		t.Fatal("the account was deleted anyway")
	}
}

func TestDeleteAccount(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	alice := h.addUser(t, "alice")

	resp := h.post(t, "/comptes/supprimer", url.Values{
		"csrf": {h.csrf(t)}, "user": {alice.ID},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("deleting returned %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "erreur=") {
		t.Fatalf("deletion was refused: %q", loc)
	}

	if _, err := h.manager.DB().UserByUsername(context.Background(), "alice"); err == nil {
		t.Fatal("the account survived deletion")
	}
}

func TestAccountActionsAreAudited(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	h.post(t, "/comptes", url.Values{
		"csrf": {h.csrf(t)}, "username": {"alice"}, "password": {testPassword},
	})
	alice, err := h.manager.DB().UserByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	h.post(t, "/comptes/motdepasse", url.Values{
		"csrf": {h.csrf(t)}, "user": {alice.ID}, "password": {"un nouveau mot de passe"},
	})
	h.post(t, "/comptes/supprimer", url.Values{
		"csrf": {h.csrf(t)}, "user": {alice.ID},
	})

	entries, err := h.manager.DB().ListAudit(context.Background(), store.AuditFilter{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}

	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		seen[e.Action] = true
		if strings.Contains(e.Detail, testPassword) || strings.Contains(e.Detail, "un nouveau mot de passe") {
			t.Fatal("the audit log recorded a password")
		}
	}
	for _, action := range []string{"user.create", "user.password", "user.delete"} {
		if !seen[action] {
			t.Fatalf("%s was not recorded; log holds %v", action, seen)
		}
	}
}

// The password form targets exactly one account, named on the page, so an
// administrator cannot reset the wrong person's password by mis-clicking a
// dropdown.
func TestPasswordFormTargetsOneAccount(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	alice := h.addUser(t, "alice")

	page := body(t, h.get(t, "/comptes/motdepasse?user="+alice.ID))
	if !strings.Contains(page, "alice") {
		t.Fatal("the page does not say whose password is being changed")
	}
	if !strings.Contains(page, `value="`+alice.ID+`"`) {
		t.Fatal("the form does not carry the target account")
	}
	if strings.Contains(page, "<select") {
		t.Fatal("the form still lets the target be picked")
	}

	if resp := h.get(t, "/comptes/motdepasse?user=nexistepas"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an unknown account returned %d, want 404", resp.StatusCode)
	}

	// And the page is administration, like the rest of the section.
	h.signInAs(t, "alice")
	if resp := h.get(t, "/comptes/motdepasse?user="+alice.ID); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a non-administrator reached the form (%d)", resp.StatusCode)
	}
}
