package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"synsec/internal/auth"
	"synsec/internal/qr"
	"synsec/internal/store"
)

// pendingCookie carries a sign-in that has passed the password and still owes
// a code.
const pendingCookie = "synsec_pending"

// pendingLife bounds the gap between the password and the code. Long enough to
// unlock a phone and find the application, short enough that a half-finished
// sign-in on a shared machine does not sit there.
const pendingLife = 5 * time.Minute

// recoveryCodeCount is how many one-time codes are issued.
const recoveryCodeCount = 10

// pendingToken ties a half-finished sign-in to this browser.
//
// Signed with a key made at start-up and never stored: a server restart cancels
// every sign-in in progress, which costs someone one password re-entry and
// means there is no key on disk to steal.
func (s *Server) pendingToken(userID string, expiry time.Time) string {
	payload := userID + "|" + strconv.FormatInt(expiry.Unix(), 10)
	mac := hmac.New(sha256.New, s.pendingKey)
	mac.Write([]byte(payload))
	return payload + "|" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// readPendingToken returns the account a pending sign-in belongs to.
func (s *Server) readPendingToken(token string, now time.Time) (string, bool) {
	parts := strings.Split(token, "|")
	if len(parts) != 3 {
		return "", false
	}
	userID, rawExpiry, signature := parts[0], parts[1], parts[2]

	expected := s.pendingToken(userID, time.Unix(mustInt(rawExpiry), 0))
	if !hmac.Equal([]byte(token), []byte(expected)) {
		return "", false
	}
	_ = signature

	if unix := mustInt(rawExpiry); unix == 0 || now.After(time.Unix(unix, 0)) {
		return "", false
	}
	return userID, true
}

func mustInt(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// startSecondFactor parks a sign-in that still owes a proof.
//
// Which proof is offered follows what the account carries: a code, a key, or
// the choice of both.
func (s *Server) startSecondFactor(w http.ResponseWriter, r *http.Request, user store.User, hasCode, hasKeys bool) {
	expiry := s.now().Add(pendingLife)
	http.SetCookie(w, &http.Cookie{
		Name:     pendingCookie,
		Value:    s.pendingToken(user.ID, expiry),
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})

	s.render(w, r, "twofactor.html", http.StatusOK, pageData{
		Title:   "Vérification",
		CSRF:    s.issueLoginToken(w),
		HasCode: hasCode,
		HasKeys: hasKeys,
	})
}

// retrySecondFactor draws the verification page again after a refusal, with
// the same choice of proofs the account actually has.
func (s *Server) retrySecondFactor(w http.ResponseWriter, r *http.Request, status int, message string) {
	data := pageData{
		Title: "Vérification", CSRF: s.issueLoginToken(w), Error: message,
		HasCode: true,
	}

	// The pending cookie says whose sign-in this is, so the page can be redrawn
	// as it was. A cookie that no longer resolves leaves the code field, which
	// is the form the message is about.
	if cookie, err := r.Cookie(pendingCookie); err == nil && cookie.Value != "" {
		if userID, ok := s.readPendingToken(cookie.Value, s.now()); ok {
			hasCode, keys, err := s.secondFactors(r.Context(), userID)
			if err != nil {
				logError(r, err)
			} else {
				data.HasCode, data.HasKeys = hasCode, keys > 0
			}
		}
	}
	s.render(w, r, "twofactor.html", status, data)
}

// finishSecondFactor checks the code and, if it holds, signs the person in.
func (s *Server) finishSecondFactor(w http.ResponseWriter, r *http.Request) {
	limitBody(w, r)
	if err := r.ParseForm(); err != nil || !validLoginToken(r) {
		s.retrySecondFactor(w, r, http.StatusForbidden,
			"Ce formulaire n'est plus valable. Recommence la connexion.")
		return
	}

	cookie, err := r.Cookie(pendingCookie)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	userID, ok := s.readPendingToken(cookie.Value, s.now())
	if !ok {
		s.clearPending(w)
		http.Redirect(w, r, "/login?expiree=1", http.StatusSeeOther)
		return
	}

	// Codes are guessable in a way passwords are not: a million possibilities
	// and thirty seconds. The same throttle as the password guards them.
	key := s.clientIP(r)
	if wait, blocked := s.throttle.blocked(key, s.now()); blocked {
		s.retrySecondFactor(w, r, http.StatusTooManyRequests,
			"Trop de tentatives. Réessaie dans "+humanDuration(wait)+".")
		return
	}

	user, err := s.vault.DB().User(r.Context(), userID)
	if err != nil {
		s.clearPending(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	code := strings.TrimSpace(r.PostFormValue("code"))
	if !s.acceptSecondFactor(r, user, code) {
		s.throttle.fail(key, s.now())
		s.audit(r, store.AuditEntry{
			ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
			Action: "auth.failed", Detail: "code de vérification incorrect",
		})
		s.retrySecondFactor(w, r, http.StatusUnauthorized, "Code incorrect.")
		return
	}

	s.throttle.succeed(key)
	s.clearPending(w)
	s.completeSignIn(w, r, user)
}

// acceptSecondFactor takes either a code from the application or one of the
// one-time recovery codes.
func (s *Server) acceptSecondFactor(r *http.Request, user store.User, code string) bool {
	secret, err := s.vault.DB().TOTPSecret(r.Context(), user.ID)
	if err != nil {
		logError(r, err)
		return false
	}
	if secret != "" && auth.VerifyTOTP(secret, code, s.now()) {
		return true
	}
	// The recovery codes are checked even when no application is enrolled: an
	// account whose only factor is a security key still has them, and they are
	// the way back in when the key is lost.
	//
	// A recovery code is spent by the check itself, so two requests racing on
	// the same one cannot both succeed.
	used, err := s.vault.DB().UseRecoveryCode(r.Context(), user.ID, normaliseRecovery(code), s.now())
	if err != nil {
		logError(r, err)
		return false
	}
	if used {
		s.audit(r, store.AuditEntry{
			ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
			Action: "auth.recovery", Detail: "code de secours utilisé",
		})
	}
	return used
}

func (s *Server) clearPending(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: pendingCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteStrictMode,
	})
}

// normaliseRecovery accepts a code however it was written down.
func normaliseRecovery(code string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

// newRecoveryCodes mints the one-time codes handed out when the second factor
// is turned on.
func newRecoveryCodes() ([]string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789" // no l, o, 0, 1

	codes := make([]string, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		raw := make([]byte, 10)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		var b strings.Builder
		for j, v := range raw {
			if j == 5 {
				b.WriteByte('-')
			}
			b.WriteByte(alphabet[int(v)%len(alphabet)])
		}
		codes = append(codes, b.String())
	}
	return codes, nil
}

// showTwoFactorSettings renders the enrolment page, or the state of an account
// that already carries a second factor.
func (s *Server) showTwoFactorSettings(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	secret, err := s.vault.DB().TOTPSecret(r.Context(), user.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	data := pageData{
		Title:  "Vérification en deux étapes",
		Nav:    "deuxfacteurs",
		User:   &user,
		CSRF:   csrfFrom(r),
		Sealed: s.vault.Sealed(),
		Notice: r.URL.Query().Get("info"),
		Error:  r.URL.Query().Get("erreur"),
	}
	if r.URL.Query().Get("enrolement") != "" {
		data.Notice = "Ce serveur exige un second facteur. Enregistre une application " +
			"ou une clé de sécurité pour accéder à tes coffres."
	}

	if secret != "" {
		data.TOTPEnabled = true
		if data.RecoveryLeft, err = s.vault.DB().CountUnusedRecoveryCodes(r.Context(), user.ID); err != nil {
			s.fail(w, r, user, err)
			return
		}
		s.render(w, r, "twofactor_settings.html", http.StatusOK, data)
		return
	}

	// A fresh secret per visit. Nothing is stored until a code proves the
	// application holds it, so abandoning this page leaves no half-enrolled
	// account behind.
	fresh, err := auth.NewTOTPSecret()
	if err != nil {
		s.fail(w, r, user, err)
		return
	}
	data.TOTPSecret = fresh
	data.TOTPGrouped = auth.FormatTOTPSecret(fresh)
	uri := auth.TOTPURI(fresh, "SYNSEC", user.Username)
	data.TOTPURI = uri

	// The code is drawn as inline SVG. An image would be a second request, and
	// the page forbids fetching anything at all; a data: URI would work but
	// costs a base64 round trip for no gain.
	if code, err := qr.Encode(uri); err == nil {
		data.TOTPQR = template.HTML(code.SVG(200, "qr")) //nolint:gosec // generated markup, no input reaches it
	} else {
		// Falling back to the typed key is a worse experience, not a broken
		// one, so a symbol that will not encode is logged and skipped.
		logError(r, err)
	}

	s.render(w, r, "twofactor_settings.html", http.StatusOK, data)
}

// enableTwoFactor turns it on, once a code proves the application holds the
// secret.
func (s *Server) enableTwoFactor(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	const back = "/parametres/verification"

	secret := strings.TrimSpace(r.PostFormValue("secret"))
	code := strings.TrimSpace(r.PostFormValue("code"))

	// The code is the proof. Storing a secret the application never accepted
	// would lock the account out at the next sign-in.
	if secret == "" || !auth.VerifyTOTP(secret, code, s.now()) {
		s.redirectWithError(w, r, back,
			"Ce code ne correspond pas. Vérifie l'heure de ton téléphone et réessaie.")
		return
	}

	codes, err := newRecoveryCodes()
	if err != nil {
		s.fail(w, r, user, err)
		return
	}
	// Stored in the form the check will use. The dash is there to be read
	// aloud and typed back, not to be part of the value; hashing the pretty
	// form here and the plain one at sign-in is how these never match.
	stored := make([]string, len(codes))
	for i, code := range codes {
		stored[i] = normaliseRecovery(code)
	}

	if err := s.vault.DB().SetTOTPSecret(r.Context(), user.ID, secret, stored); err != nil {
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "auth.2fa.enable", Target: user.Username,
	})

	s.render(w, r, "twofactor_codes.html", http.StatusOK, pageData{
		Title:         "Codes de secours",
		Nav:           "deuxfacteurs",
		User:          &user,
		CSRF:          csrfFrom(r),
		Sealed:        s.vault.Sealed(),
		RecoveryCodes: codes,
	})
}

// disableTwoFactor turns it off, against the account password.
//
// The password is asked for again because a browser left open is exactly the
// situation the second factor exists to survive.
func (s *Server) disableTwoFactor(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	const back = "/parametres/verification"

	_, ok, busy := s.verify(r, user.Username, r.PostFormValue("password"))
	if busy {
		s.redirectWithError(w, r, back,
			"Le serveur est momentanément surchargé. Réessaie dans quelques secondes.")
		return
	}
	if !ok {
		s.redirectWithError(w, r, back, "Mot de passe incorrect.")
		return
	}

	// A security key left on the account means the second factor is not being
	// turned off, only this half of it - and the recovery codes still have a
	// job to do.
	keys, err := s.vault.DB().CountSecurityKeys(r.Context(), user.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}
	// The server may insist on a second factor. Turning off the last one would
	// only bounce this account into the enrolment page, so it is refused here
	// with a reason rather than allowed and undone a moment later.
	if s.requiresFactor() && keys == 0 {
		s.redirectWithError(w, r, back,
			"Ce serveur exige un second facteur. Enregistre une clé de sécurité avant de retirer l'application.")
		return
	}

	if keys > 0 {
		err = s.vault.DB().ClearTOTPSecret(r.Context(), user.ID)
	} else {
		err = s.vault.DB().ClearTOTP(r.Context(), user.ID)
	}
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "auth.2fa.disable", Target: user.Username,
	})
	if keys > 0 {
		s.redirectWithNotice(w, r, back,
			"Application retirée. "+plural(keys, "Ta clé de sécurité protège", "Tes clés de sécurité protègent")+" toujours ce compte.")
		return
	}
	s.redirectWithNotice(w, r, back,
		"Vérification en deux étapes désactivée. Ton mot de passe redevient la seule preuve.")
}
