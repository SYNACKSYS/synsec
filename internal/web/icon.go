package web

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"net/http"
)

// L'icône, dessinée par SYNSEC lui-même.
//
// Posée sur l'écran d'accueil d'un téléphone, une adresse web devient une
// icône et un nom. Sans icône, c'est un carré blanc au milieu des autres
// applications - et l'impression, immédiate, est que ce n'est pas une vraie
// application.
//
// Dessinée en géométrie plutôt qu'importée : le dépôt reste du texte, il n'y
// a pas de fichier binaire à régénérer quand la couleur change, et rien à
// charger depuis ailleurs. C'est le même parti pris que pour les QR codes.
//
// Un trou de serrure : ça se lit à quarante pixels, ce qui est la seule
// exigence réelle d'une icône.

// Les couleurs de la marque. Fixes, indépendantes du thème : une icône
// d'écran d'accueil ne change pas quand le téléphone passe en sombre.
var (
	iconBackground = color.NRGBA{R: 0x4f, G: 0x46, B: 0xe5, A: 0xff}
	iconForeground = color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
)

// Le trou de serrure, en fractions du côté. Le cercle en haut, la fente qui
// s'évase en dessous.
const (
	holeCenterY  = 0.43
	holeRadius   = 0.155
	slotTop      = 0.43
	slotBottom   = 0.755
	slotHalfTop  = 0.055
	slotHalfBase = 0.105
)

// iconPNG draws the mark at the requested size.
//
// Fond plein bord à bord, sans coins arrondis : iOS et Android découpent
// eux-mêmes la forme qu'ils veulent, et une icône déjà arrondie se retrouve
// arrondie deux fois, avec un liseré du fond de l'écran dans les angles.
func iconPNG(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("web: taille d'icône invalide : %d", size)
	}
	img := image.NewNRGBA(image.Rect(0, 0, size, size))

	// Quatre points par pixel dans chaque direction : le bord du cercle est
	// lissé au lieu d'être un escalier. Sans ça, une icône de 180 pixels a
	// l'air d'avoir été dessinée à la main sur un écran de 1995.
	const samples = 4
	step := 1.0 / float64(size*samples)

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			hits := 0
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					u := (float64(x*samples+sx) + 0.5) * step
					v := (float64(y*samples+sy) + 0.5) * step
					if insideKeyhole(u, v) {
						hits++
					}
				}
			}
			coverage := float64(hits) / float64(samples*samples)
			img.SetNRGBA(x, y, blend(iconBackground, iconForeground, coverage))
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("web: encoding the icon: %w", err)
	}
	return buf.Bytes(), nil
}

// insideKeyhole reports whether a point of the unit square falls in the mark.
func insideKeyhole(u, v float64) bool {
	// Le cercle.
	dx, dy := u-0.5, v-holeCenterY
	if math.Hypot(dx, dy) <= holeRadius {
		return true
	}
	// La fente, qui s'élargit vers le bas.
	if v < slotTop || v > slotBottom {
		return false
	}
	t := (v - slotTop) / (slotBottom - slotTop)
	half := slotHalfTop + t*(slotHalfBase-slotHalfTop)
	return math.Abs(u-0.5) <= half
}

func blend(back, front color.NRGBA, k float64) color.NRGBA {
	if k <= 0 {
		return back
	}
	if k >= 1 {
		return front
	}
	mix := func(a, b uint8) uint8 {
		return uint8(math.Round(float64(a)*(1-k) + float64(b)*k))
	}
	return color.NRGBA{R: mix(back.R, front.R), G: mix(back.G, front.G), B: mix(back.B, front.B), A: 0xff}
}

// iconSVG is the same mark for a browser tab, where a vector stays sharp at
// whatever size the browser feels like asking for.
//
// Written from the same constants as the drawing above, so the two cannot
// drift apart the day somebody moves the keyhole.
func iconSVG() string {
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <rect width="100" height="100" rx="22" fill="#%02x%02x%02x"/>
  <path fill="#%02x%02x%02x" d="M50 %.1f m-%.1f 0 a%.1f %.1f 0 1 0 %.1f 0 a%.1f %.1f 0 1 0 -%.1f 0 Z
    M%.1f %.1f L%.1f %.1f L%.1f %.1f L%.1f %.1f Z"/>
</svg>`,
		iconBackground.R, iconBackground.G, iconBackground.B,
		iconForeground.R, iconForeground.G, iconForeground.B,
		holeCenterY*100, holeRadius*100, holeRadius*100, holeRadius*100,
		holeRadius*200, holeRadius*100, holeRadius*100, holeRadius*200,
		50-slotHalfTop*100, slotTop*100,
		50+slotHalfTop*100, slotTop*100,
		50+slotHalfBase*100, slotBottom*100,
		50-slotHalfBase*100, slotBottom*100)
}

// manifest is what turns the address into an application on a home screen.
//
// "standalone" is the whole point: opened from the home screen, SYNSEC runs
// without the browser's address bar, which is the difference between a
// bookmark and an application.
func manifestJSON() string {
	return `{
  "name": "SYNSEC",
  "short_name": "SYNSEC",
  "description": "Tes secrets, chez toi.",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "orientation": "portrait-primary",
  "background_color": "#0f1115",
  "theme_color": "#16181d",
  "lang": "fr",
  "icons": [
    { "src": "/icone-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any" },
    { "src": "/icone-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any" },
    { "src": "/icone-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable" }
  ]
}`
}

// iconSizes are the ones the platforms ask for: 180 for the iOS home screen,
// 192 and 512 for the manifest.
var iconSizes = []int{180, 192, 512}

// drawIcons renders them once, at start-up, so no request pays for it.
func drawIcons() (map[int][]byte, error) {
	out := make(map[int][]byte, len(iconSizes))
	for _, size := range iconSizes {
		data, err := iconPNG(size)
		if err != nil {
			return nil, err
		}
		out[size] = data
	}
	return out, nil
}

// serveIcon hands out one of the rendered sizes.
//
// Public, like the sign-in page: a home screen fetches the icon before anybody
// has signed in, and an icon says nothing a visitor could not see by looking
// at the front page anyway.
func (s *Server) serveIcon(size int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, ok := s.icons[size]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(data) //nolint:errcheck // a dropped icon is not worth a log line
	}
}

func (s *Server) serveIconSVG(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	fmt.Fprint(w, iconSVG())
}

func (s *Server) serveManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	fmt.Fprint(w, manifestJSON())
}
