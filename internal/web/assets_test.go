package web

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// An upgrade has to reach a phone that already visited.
//
// The assets are cached for a day, which is right: they are identical bytes
// for the life of a version. What was wrong is that their address never
// changed either, so the cache had no way to know a new interface existed and
// the owner saw the old one for another day.
func TestTheStyleSheetAddressChangesWithItsContent(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	page := body(t, h.get(t, "/"))
	found := regexp.MustCompile(`/static/style\.css\?v=([0-9a-f]{8})`).FindStringSubmatch(page)
	if found == nil {
		t.Fatalf("la feuille de style n'a pas d'empreinte dans son adresse")
	}

	// The same build always says the same thing, or every page load would
	// refetch and the caching would be pointless.
	again := body(t, h.get(t, "/"))
	if !strings.Contains(again, found[0]) {
		t.Error("l'empreinte change d'une page à l'autre")
	}

	// The sign-in page loads the same sheet and must carry it too, otherwise
	// the one page everybody sees first is the one stuck on the old style.
	// Read from a session-less harness, because a signed-in visitor is simply
	// sent home.
	anon := newHarness(t)
	if !strings.Contains(body(t, anon.get(t, "/login")), "style.css?v=") {
		t.Error("la page de connexion n'a pas l'empreinte")
	}
}

func TestTheAssetsAreStillCachedHard(t *testing.T) {
	h := newHarness(t)
	resp := h.get(t, "/static/style.css")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("la feuille de style répond %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "max-age=") {
		t.Fatalf("Cache-Control = %q", got)
	}
}
