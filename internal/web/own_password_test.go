package web

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"synsec/internal/auth"
)

// currentPassword reports whether a password opens an account, read straight
// from the store so the assertion does not depend on the sign-in page.
func (h *harness) currentPassword(t *testing.T, username, password string) bool {
	t.Helper()
	ctx := context.Background()

	user, err := h.manager.DB().UserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	cred, err := h.manager.DB().UserCredentials(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserCredentials: %v", err)
	}
	return auth.VerifyPassword(cred, password)
}

func TestChangeOwnPassword(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	resp := h.post(t, "/parametres/motdepasse", url.Values{
		"csrf":     {h.csrf(t)},
		"current":  {testPassword},
		"password": {"un tout nouveau mot de passe"},
		"confirm":  {"un tout nouveau mot de passe"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("changing the password returned %d", resp.StatusCode)
	}

	if !h.currentPassword(t, "cyril", "un tout nouveau mot de passe") {
		t.Fatal("the new password does not open the account")
	}
	if h.currentPassword(t, "cyril", testPassword) {
		t.Fatal("the old password still opens the account")
	}

	// The browser that did it stays signed in - it just proved who it was.
	if resp := h.get(t, "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the page that changed the password was signed out (%d)", resp.StatusCode)
	}
}

// A password changed because it may have leaked must not leave the browsers it
// leaked to signed in.
func TestChangingOwnPasswordClosesOtherSessions(t *testing.T) {
	h := newHarness(t)

	h.signIn(t)
	elsewhere := h.client.Jar

	// A second browser for the same account.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	h.client.Jar = jar
	h.signIn(t)

	h.post(t, "/parametres/motdepasse", url.Values{
		"csrf":     {h.csrf(t)},
		"current":  {testPassword},
		"password": {"un tout nouveau mot de passe"},
		"confirm":  {"un tout nouveau mot de passe"},
	})

	h.client.Jar = elsewhere
	if resp := h.get(t, "/"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("the other browser is still signed in (%d)", resp.StatusCode)
	}
}

func TestOwnPasswordNeedsTheCurrentOne(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	cases := map[string]url.Values{
		"mot de passe actuel faux": {
			"current":  {"pas le bon"},
			"password": {"un tout nouveau mot de passe"},
			"confirm":  {"un tout nouveau mot de passe"},
		},
		"confirmation différente": {
			"current":  {testPassword},
			"password": {"un tout nouveau mot de passe"},
			"confirm":  {"autre chose entièrement"},
		},
		"nouveau trop court": {
			"current":  {testPassword},
			"password": {"court"},
			"confirm":  {"court"},
		},
	}

	for name, form := range cases {
		form.Set("csrf", h.csrf(t))
		resp := h.post(t, "/parametres/motdepasse", form)
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
			t.Errorf("%s was accepted: %q", name, loc)
		}
	}

	if !h.currentPassword(t, "cyril", testPassword) {
		t.Fatal("a refused change went through anyway")
	}
}
