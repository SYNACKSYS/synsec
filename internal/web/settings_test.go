package web

import (
	"io/fs"
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

// The palette rides on the same element as the size, so both have to reach
// every page and neither may disturb the other.
func TestThePaletteAppliesToEveryPage(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	if page := body(t, h.get(t, "/")); strings.Contains(page, "theme-") {
		t.Fatal("a palette is applied before anything was chosen")
	}

	resp := h.post(t, "/parametres/apparence", url.Values{
		"csrf": {h.csrf(t)}, "scale": {"80"}, "theme": {"laiton"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("saving the palette returned %d", resp.StatusCode)
	}

	page := body(t, h.get(t, "/"))
	if !strings.Contains(page, `class="scale-80 theme-laiton"`) {
		t.Fatal("the home page carries neither the size nor the palette")
	}
	if page := body(t, h.get(t, "/parametres")); !strings.Contains(page, "theme-laiton") {
		t.Fatal("the settings page is not drawn in the chosen palette")
	}

	// Back to the default: the class must disappear rather than be written out.
	h.post(t, "/parametres/apparence", url.Values{
		"csrf": {h.csrf(t)}, "scale": {"80"}, "theme": {"ardoise"},
	})
	if page := body(t, h.get(t, "/")); strings.Contains(page, "theme-") {
		t.Fatal("the default palette is written into the page")
	}
}

// The palette is written into a class name, so anything outside the list must
// be refused rather than reflected into the markup.
func TestAnUnknownPaletteIsRefused(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	for _, bad := range []string{"neon", "laiton\" onload=\"x", "../"} {
		resp := h.post(t, "/parametres/apparence", url.Values{
			"csrf": {h.csrf(t)}, "scale": {"100"}, "theme": {bad},
		})
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
			t.Fatalf("the palette %q was accepted", bad)
		}
	}
}

// Sending only the size must leave the palette where it was, since the two
// share one form.
func TestSavingTheSizeAloneKeepsThePalette(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	h.post(t, "/parametres/apparence", url.Values{
		"csrf": {h.csrf(t)}, "scale": {"100"}, "theme": {"laiton"},
	})
	h.post(t, "/parametres/apparence", url.Values{
		"csrf": {h.csrf(t)}, "scale": {"90"},
	})

	if page := body(t, h.get(t, "/")); !strings.Contains(page, "theme-laiton") {
		t.Fatal("saving the size alone reset the palette")
	}
}

// The form carries what the preview needs: the two defaults, so the script
// knows which values the server writes into the page and which it leaves out.
func TestTheAppearanceFormCarriesItsDefaults(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	page := body(t, h.get(t, "/parametres"))
	for _, want := range []string{
		"data-appearance",
		`data-default-scale="100"`,
		`data-default-theme="ardoise"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the appearance form carries no %s", want)
		}
	}
}

// A palette offered on the page and absent from the stylesheet would be a
// choice that changes nothing - and nothing about saving it would fail.
func TestEveryOfferedPaletteExistsInTheStylesheet(t *testing.T) {
	assets, err := staticFS()
	if err != nil {
		t.Fatalf("staticFS: %v", err)
	}
	sheet, err := fs.ReadFile(assets, "style.css")
	if err != nil {
		t.Fatalf("reading the stylesheet: %v", err)
	}

	for _, theme := range offeredThemes {
		if theme.Value == defaultTheme {
			// The default is the plain stylesheet; it has no class of its own.
			continue
		}
		if !strings.Contains(string(sheet), ".theme-"+theme.Value) {
			t.Errorf("the palette %q is offered but the stylesheet defines nothing for it", theme.Value)
		}
	}
}

// Veilleuse is the one palette that ignores the system setting, so it must not
// carry a light-scheme block that would undo the point of it.
func TestVeilleuseStaysDark(t *testing.T) {
	assets, _ := staticFS()
	sheet, err := fs.ReadFile(assets, "style.css")
	if err != nil {
		t.Fatalf("reading the stylesheet: %v", err)
	}

	block := string(sheet)
	start := strings.Index(block, ".theme-veilleuse")
	if start < 0 {
		t.Fatal("no Veilleuse block")
	}
	// Its declarations must sit outside any colour-scheme query, which is what
	// makes the palette the same at noon and at three in the morning.
	if strings.Count(block[start:], "prefers-color-scheme") != 0 {
		t.Error("Veilleuse depends on the system colour scheme")
	}
}
