package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"synsec/internal/auth"
	"synsec/internal/store"
)

// Preference keys. They live in one table keyed by account, so adding a
// setting means adding a constant here and a control on the page - no schema
// change, and an older binary meeting an unknown key just ignores it.
const (
	settingScale = "ui.scale"
	settingTheme = "ui.theme"
)

// defaultTheme is the palette the interface has always had.
const defaultTheme = "ardoise"

// offeredThemes are the palettes on offer. A short list for the same reason as
// the sizes: every one here has been looked at.
var offeredThemes = []themeRow{
	{Value: "ardoise", Label: "Ardoise (par défaut)",
		Note: "Gris et indigo, clair ou sombre selon ton système."},
	{Value: "laiton", Label: "Laiton",
		Note: "Zinc et laiton, angles droits. Le vestiaire à clés plutôt que le tableau de bord."},
}

// defaultScale is the browser's own idea of a comfortable size.
const defaultScale = 100

// offeredScales are the sizes the page proposes.
//
// A short list rather than a free number: every value here is one the interface
// has been looked at in, and there is no way to land on something unreadable
// and then be unable to find the control to undo it.
var offeredScales = []int{80, 90, 100, 110, 125}

// scaleRow is one choice on the appearance page.
type scaleRow struct {
	Value   int
	Label   string
	Current bool
}

// themeRow is one palette on the same page.
type themeRow struct {
	Value   string
	Label   string
	Note    string
	Current bool
}

// showSettings renders the visitor's own preferences.
func (s *Server) showSettings(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	scale := scaleFrom(r)

	rows := make([]scaleRow, 0, len(offeredScales))
	for _, v := range offeredScales {
		label := strconv.Itoa(v) + " %"
		if v == defaultScale {
			label += " (par défaut)"
		}
		rows = append(rows, scaleRow{Value: v, Label: label, Current: v == scale})
	}

	current := themeFrom(r)
	themes := make([]themeRow, 0, len(offeredThemes))
	for _, t := range offeredThemes {
		t.Current = t.Value == current
		themes = append(themes, t)
	}

	s.render(w, r, "settings.html", http.StatusOK, pageData{
		Title:       "Paramètres",
		Nav:         "parametres",
		User:        &user,
		CSRF:        csrfFrom(r),
		Sealed:      s.vault.Sealed(),
		Scales:      rows,
		Themes:      themes,
		SessionIdle: humanDuration(s.sessionIdle),
		Notice:      r.URL.Query().Get("info"),
		Error:       r.URL.Query().Get("erreur"),
	})
}

// saveAppearance records the display size.
func (s *Server) saveAppearance(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	const back = "/parametres"

	scale, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("scale")))
	if err != nil || !scaleOffered(scale) {
		s.redirectWithError(w, r, back, "Cette taille d'affichage n'existe pas.")
		return
	}

	// An absent palette means "leave it alone" rather than "back to the
	// default": the two settings share one form, and a caller that sends only
	// the size must not quietly reset the other.
	theme := strings.TrimSpace(r.PostFormValue("theme"))
	if theme != "" && !themeOffered(theme) {
		s.redirectWithError(w, r, back, "Cette palette n'existe pas.")
		return
	}

	if err := s.vault.DB().SetUserSetting(
		r.Context(), user.ID, settingScale, strconv.Itoa(scale)); err != nil {
		s.fail(w, r, user, err)
		return
	}
	if theme != "" {
		if err := s.vault.DB().SetUserSetting(
			r.Context(), user.ID, settingTheme, theme); err != nil {
			s.fail(w, r, user, err)
			return
		}
	}

	s.redirectWithNotice(w, r, back, "Apparence enregistrée.")
}

// showOwnPassword renders the form for changing one's own password.
//
// Separate from the administrator's version: this one asks for the current
// password, so a browser left open on the kitchen tablet is not enough to lock
// its owner out of their own account.
func (s *Server) showOwnPassword(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	s.render(w, r, "own_password.html", http.StatusOK, pageData{
		Title:  "Mot de passe",
		Nav:    "motdepasse",
		User:   &user,
		CSRF:   csrfFrom(r),
		Sealed: s.vault.Sealed(),
		Notice: r.URL.Query().Get("info"),
		Error:  r.URL.Query().Get("erreur"),
	})
}

// changeOwnPassword replaces the signed-in person's own password.
func (s *Server) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	const back = "/parametres/motdepasse"

	_, ok, busy := s.verify(r, user.Username, r.PostFormValue("current"))
	if busy {
		s.redirectWithError(w, r, back,
			"Le serveur est momentanément surchargé. Réessaie dans quelques secondes.")
		return
	}
	if !ok {
		s.audit(r, store.AuditEntry{
			ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
			Action: "auth.failed", Detail: "mot de passe actuel incorrect",
		})
		s.redirectWithError(w, r, back, "Ton mot de passe actuel est incorrect.")
		return
	}

	password := r.PostFormValue("password")
	if password != r.PostFormValue("confirm") {
		s.redirectWithError(w, r, back, "Les deux nouveaux mots de passe ne correspondent pas.")
		return
	}

	if err := auth.CheckPasswordStrength(password, user.Username); err != nil {
		s.redirectWithError(w, r, back, passwordProblem(err))
		return
	}
	cred, err := auth.HashPassword(password)
	if err != nil {
		s.redirectWithError(w, r, back, passwordProblem(err))
		return
	}
	if err := s.vault.DB().SetUserCredentials(r.Context(), user.ID, cred); err != nil {
		s.fail(w, r, user, err)
		return
	}

	// Every session goes, including this one: changing a password because it
	// may have leaked is pointless if the browsers it leaked to keep working.
	// This browser is then handed a new one, so the person who just typed the
	// old password correctly is not signed out of the page they are on.
	if err := s.vault.DB().DeleteUserSessions(r.Context(), user.ID); err != nil {
		logError(r, err)
	}
	if err := s.reissueSession(w, r, user); err != nil {
		logError(r, err)
		s.clearSessionCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "user.password", Target: user.Username,
	})
	s.redirectWithNotice(w, r, back,
		"Mot de passe changé. Tes autres sessions ont été fermées.")
}

// reissueSession signs this browser back in after its session was dropped.
func (s *Server) reissueSession(w http.ResponseWriter, r *http.Request, user store.User) error {
	token, hash, err := auth.NewSessionToken()
	if err != nil {
		return err
	}

	now := s.now()
	expiry := auth.SessionExpiryWith(s.sessionIdle, now, now)
	session := store.Session{
		UserID:    user.ID,
		ExpiresAt: expiry,
		UserAgent: truncate(r.UserAgent(), 200),
		IP:        s.clientIP(r),
	}
	if err := s.vault.DB().CreateSession(r.Context(), &session, hash); err != nil {
		return err
	}

	s.setSessionCookie(w, token, expiry)
	return nil
}

func themeOffered(v string) bool {
	for _, t := range offeredThemes {
		if t.Value == v {
			return true
		}
	}
	return false
}

// loadTheme reads an account's palette, falling back to the default when the
// setting is absent or names something this build no longer offers.
func (s *Server) loadTheme(ctx context.Context, user store.User) string {
	raw, err := s.vault.DB().UserSetting(ctx, user.ID, settingTheme, "")
	if err != nil || !themeOffered(raw) {
		return defaultTheme
	}
	return raw
}

// themeFrom reads the palette resolved by requireLogin for this request.
func themeFrom(r *http.Request) string {
	if v, ok := r.Context().Value(ctxTheme).(string); ok && v != "" {
		return v
	}
	return defaultTheme
}

func scaleOffered(v int) bool {
	for _, ok := range offeredScales {
		if ok == v {
			return true
		}
	}
	return false
}

// loadScale reads an account's display size.
//
// A preference nobody set, or one left over from a version that offered other
// values, falls back to the default rather than failing the page: the interface
// still has to render even when the setting cannot be read.
func (s *Server) loadScale(ctx context.Context, user store.User) int {
	raw, err := s.vault.DB().UserSetting(ctx, user.ID, settingScale, "")
	if err != nil || raw == "" {
		return defaultScale
	}
	v, err := strconv.Atoi(raw)
	if err != nil || !scaleOffered(v) {
		return defaultScale
	}
	return v
}

// scaleFrom reads the size resolved by requireLogin for this request.
func scaleFrom(r *http.Request) int {
	if v, ok := r.Context().Value(ctxScale).(int); ok && v != 0 {
		return v
	}
	return defaultScale
}
