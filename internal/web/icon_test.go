package web

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	_ "image/png"
	"net/http"
	"strings"
	"testing"
)

// Posée sur l'écran d'accueil d'un téléphone, une adresse doit devenir une
// application : une icône, un nom, et une fenêtre sans barre d'adresse.

func TestTheIconIsDrawnAtEverySizeAPlatformAsksFor(t *testing.T) {
	h := newHarness(t)

	for _, size := range iconSizes {
		path := "/icone-" + itoa(size) + ".png"
		resp := h.get(t, path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s répond %d", path, resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Type"); got != "image/png" {
			t.Errorf("%s est servi en %q", path, got)
		}

		img, format, err := image.Decode(bytes.NewReader([]byte(body(t, h.get(t, path)))))
		if err != nil {
			t.Fatalf("%s n'est pas une image lisible : %v", path, err)
		}
		if format != "png" {
			t.Errorf("%s est un %s", path, format)
		}
		if b := img.Bounds(); b.Dx() != size || b.Dy() != size {
			t.Errorf("%s fait %dx%d", path, b.Dx(), b.Dy())
		}
	}
}

// Une icône entièrement d'une seule couleur est une icône ratée : c'est ce
// qu'on obtient quand le dessin déborde, ou quand il ne dessine rien.
func TestTheIconHasBothAMarkAndABackground(t *testing.T) {
	data, err := iconPNG(180)
	if err != nil {
		t.Fatalf("iconPNG: %v", err)
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Le coin est le fond, le centre du cercle est la marque. Passé par une
	// variable : une constante fractionnaire ne se convertit pas en entier.
	var centre float64 = holeCenterY * 180
	corner := color.NRGBAModel.Convert(img.At(2, 2)).(color.NRGBA)
	middle := color.NRGBAModel.Convert(img.At(90, int(centre))).(color.NRGBA)

	if corner != iconBackground {
		t.Errorf("le coin n'est pas le fond : %+v", corner)
	}
	if middle != iconForeground {
		t.Errorf("le centre du trou de serrure n'est pas la marque : %+v", middle)
	}
	// La marque occupe une part raisonnable du carré. Un trou de serrure
	// minuscule disparaît à quarante pixels ; un trou qui remplit tout n'est
	// plus une forme reconnaissable.
	marque := 0
	for y := 0; y < 180; y++ {
		for x := 0; x < 180; x++ {
			c := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
			if c.R > 0xc0 && c.G > 0xc0 && c.B > 0xc0 {
				marque++
			}
		}
	}
	part := float64(marque) / float64(180*180)
	if part < 0.05 || part > 0.2 {
		t.Errorf("la marque couvre %.1f %% du carré", part*100)
	}

	// Et le fond est opaque partout : une icône translucide sur un écran
	// d'accueil laisse voir le papier peint au travers.
	b := img.Bounds()
	for _, p := range []image.Point{{X: 0, Y: 0}, {X: b.Dx() - 1, Y: 0}, {X: 0, Y: b.Dy() - 1}, {X: b.Dx() - 1, Y: b.Dy() - 1}} {
		if _, _, _, a := img.At(p.X, p.Y).RGBA(); a != 0xffff {
			t.Errorf("le coin %v est translucide", p)
		}
	}
}

func TestTheManifestMakesItAnApplication(t *testing.T) {
	h := newHarness(t)

	resp := h.get(t, "/manifest.webmanifest")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("le manifeste répond %d", resp.StatusCode)
	}

	var m struct {
		Name      string `json:"name"`
		StartURL  string `json:"start_url"`
		Display   string `json:"display"`
		ThemeColo string `json:"theme_color"`
		Icons     []struct {
			Src   string `json:"src"`
			Sizes string `json:"sizes"`
		} `json:"icons"`
	}
	if err := json.Unmarshal([]byte(body(t, h.get(t, "/manifest.webmanifest"))), &m); err != nil {
		t.Fatalf("le manifeste n'est pas du JSON : %v", err)
	}

	if m.Display != "standalone" {
		t.Errorf("display = %q : sans « standalone » l'application garde la barre d'adresse", m.Display)
	}
	if m.Name == "" || m.StartURL == "" {
		t.Error("le manifeste n'a ni nom ni adresse de départ")
	}
	if len(m.Icons) == 0 {
		t.Fatal("le manifeste ne déclare aucune icône")
	}
	// Chaque icône annoncée doit exister, sinon l'installation échoue sans
	// rien dire.
	for _, icon := range m.Icons {
		if code := h.get(t, icon.Src).StatusCode; code != http.StatusOK {
			t.Errorf("le manifeste annonce %s, qui répond %d", icon.Src, code)
		}
	}
}

// Le manifeste et l'icône sont demandés avant toute connexion.
func TestTheIconAndManifestAreServedToAnyone(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/icone.svg", "/icone-180.png", "/manifest.webmanifest"} {
		if code := h.get(t, path).StatusCode; code != http.StatusOK {
			t.Errorf("%s répond %d à un visiteur non connecté", path, code)
		}
	}
}

func TestThePagesPointAtTheIconAndTheManifest(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	page := body(t, h.get(t, "/"))
	for _, want := range []string{
		`rel="icon" href="/icone.svg"`,
		`rel="apple-touch-icon" href="/icone-180.png"`,
		`rel="manifest" href="/manifest.webmanifest"`,
		`name="theme-color"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("la page ne porte pas %s", want)
		}
	}
}
