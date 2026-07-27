package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDisplaySizeAppliesToEveryPage(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	// Nothing chosen yet: the layout must not force a size.
	if page := body(t, h.get(t, "/")); strings.Contains(page, "scale-") {
		t.Fatal("a display size is applied before anything was chosen")
	}

	resp := h.post(t, "/parametres/apparence", url.Values{
		"csrf": {h.csrf(t)}, "scale": {"80"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("saving the display size returned %d", resp.StatusCode)
	}

	// It has to reach pages other than the one it was set on.
	if page := body(t, h.get(t, "/")); !strings.Contains(page, `class="scale-80"`) {
		t.Fatal("the home page is not drawn at the chosen size")
	}
	if page := body(t, h.get(t, "/parametres")); !strings.Contains(page, `class="scale-80"`) {
		t.Fatal("the settings page is not drawn at the chosen size")
	}
}

// The size is written into a class name, so anything outside the offered list
// must be refused rather than reflected into the page.
func TestUnknownDisplaySizeIsRefused(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	for _, bad := range []string{"42", "0", "", "80'; --", "100%"} {
		resp := h.post(t, "/parametres/apparence", url.Values{
			"csrf": {h.csrf(t)}, "scale": {bad},
		})
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
			t.Errorf("scale %q was accepted: %q", bad, loc)
		}
	}

	if page := body(t, h.get(t, "/")); strings.Contains(page, "scale-") {
		t.Fatal("a refused size was applied anyway")
	}
}

// A preference belongs to one account, not to the server.
func TestDisplaySizeIsPerAccount(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	h.addUser(t, "alice")

	h.post(t, "/parametres/apparence", url.Values{
		"csrf": {h.csrf(t)}, "scale": {"125"},
	})

	h.signInAs(t, "alice")
	if page := body(t, h.get(t, "/")); strings.Contains(page, "scale-") {
		t.Fatal("alice inherited another account's display size")
	}
}
