package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"synsec/internal/store"
	"synsec/internal/webauthn"
)

// Security keys - the little USB or NFC objects, and the ones built into a
// phone or a laptop.
//
// They are a second factor like the six-digit code, with one difference that
// matters more than any other: what the key signs includes the domain it is
// answering to. A page that merely looks like this server gets nothing, where
// a code typed into that page would have been handed straight over. That is
// the whole reason to offer them.
//
// Both ceremonies follow the same shape. The server poses a random challenge,
// the browser takes it to the key, and the answer comes back to be checked
// against what was asked. The challenge is kept here rather than in a cookie,
// so that using it once consumes it.

const (
	// challengeLife is how long a ceremony may take. Long enough to find the
	// key in a drawer, short enough that an abandoned one does not linger.
	challengeLife = 3 * time.Minute

	// codeStashLife bounds how long freshly minted recovery codes wait to be
	// displayed. They are shown on the page immediately after registration; a
	// browser that never arrives leaves nothing behind.
	codeStashLife = 10 * time.Minute
)

// challengeStore holds the questions currently outstanding.
//
// In memory, like the sign-in throttle: a restart cancels every ceremony in
// progress, which costs one retry, and nothing about a challenge is worth
// writing to disk.
type challengeStore struct {
	mu      sync.Mutex
	entries map[string]challengeEntry
}

type challengeEntry struct {
	value   []byte
	expires time.Time
}

func newChallengeStore() *challengeStore {
	return &challengeStore{entries: make(map[string]challengeEntry)}
}

// issue poses a new question, replacing any the same key had outstanding.
func (c *challengeStore) issue(key string, now time.Time) ([]byte, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.forgetExpired(now)
	c.entries[key] = challengeEntry{value: value, expires: now.Add(challengeLife)}
	return value, nil
}

// take returns a challenge and forgets it, so one answer is all it accepts.
func (c *challengeStore) take(key string, now time.Time) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	delete(c.entries, key)
	if !ok || now.After(entry.expires) {
		return nil, false
	}
	return entry.value, true
}

func (c *challengeStore) forgetExpired(now time.Time) {
	for key, entry := range c.entries {
		if now.After(entry.expires) {
			delete(c.entries, key)
		}
	}
}

// codeStash holds recovery codes between the moment they are minted and the
// page that shows them. One batch per account, shown once, then gone.
type codeStash struct {
	mu      sync.Mutex
	batches map[string]codeBatch
}

type codeBatch struct {
	codes   []string
	expires time.Time
}

func newCodeStash() *codeStash { return &codeStash{batches: make(map[string]codeBatch)} }

func (s *codeStash) put(userID string, codes []string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, batch := range s.batches {
		if now.After(batch.expires) {
			delete(s.batches, id)
		}
	}
	s.batches[userID] = codeBatch{codes: codes, expires: now.Add(codeStashLife)}
}

func (s *codeStash) take(userID string, now time.Time) ([]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	batch, ok := s.batches[userID]
	delete(s.batches, userID)
	if !ok || now.After(batch.expires) {
		return nil, false
	}
	return batch.codes, true
}

// relyingParty is the identity this server claims during a ceremony.
//
// Both halves come from the address the browser actually used, because a
// household server has no canonical name: the same machine is reached as
// "synsec.maison" from a laptop and as "synsec" from a phone, and a credential
// registered under one name will not answer to the other. The browser refuses
// anything that does not match the page it is on, so this cannot be used to
// widen the scope - only to name it.
func (s *Server) relyingParty(r *http.Request) webauthn.Config {
	host := r.Host

	scheme := "https"
	if !s.secureCookies {
		// Only ever the case in tests; the server has no plain-HTTP mode.
		scheme = "http"
	}

	name := host
	if bare, _, err := net.SplitHostPort(host); err == nil {
		name = bare
	}
	return webauthn.Config{RPID: name, Origin: scheme + "://" + host}
}

// The JSON the browser is given and gives back. Binary fields travel as
// base64url, which is what the WebAuthn API expects on the way in and what the
// script produces on the way out.

type credentialDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type registrationOptions struct {
	Challenge              string                 `json:"challenge"`
	RP                     map[string]string      `json:"rp"`
	User                   map[string]string      `json:"user"`
	PubKeyCredParams       []map[string]any       `json:"pubKeyCredParams"`
	Timeout                int                    `json:"timeout"`
	ExcludeCredentials     []credentialDescriptor `json:"excludeCredentials"`
	AuthenticatorSelection map[string]string      `json:"authenticatorSelection"`
	Attestation            string                 `json:"attestation"`
}

type assertionOptions struct {
	Challenge        string                 `json:"challenge"`
	RPID             string                 `json:"rpId"`
	Timeout          int                    `json:"timeout"`
	AllowCredentials []credentialDescriptor `json:"allowCredentials"`
	UserVerification string                 `json:"userVerification"`
}

// answer is what the script sends back, whichever ceremony it ran.
type answer struct {
	ID                string `json:"id"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AttestationObject string `json:"attestationObject"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
}

func decodeB64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
func encodeB64(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }

// writeJSON answers the script. Its replies are never cached and never HTML.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("web: writing a JSON reply: %v", err)
	}
}

// refuse tells the script what to show, in words the person reading them can
// act on. Never the underlying reason: that goes to the operator's log.
func refuse(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"message": message})
}

// showSecurityKeys lists the keys on an account and offers to add one.
func (s *Server) showSecurityKeys(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	keys, err := s.vault.DB().SecurityKeys(r.Context(), user.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	// Whether an application is enrolled decides what the page may offer: with
	// no other factor, removing the last key is refused rather than shown.
	hasCode, _, err := s.secondFactors(r.Context(), user.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}

	rows := make([]securityKeyRow, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, securityKeyRow{
			ID:         key.ID,
			Name:       key.Name,
			CreatedAt:  key.CreatedAt,
			LastUsedAt: key.LastUsedAt,
		})
	}

	s.render(w, r, "securitykeys.html", http.StatusOK, pageData{
		Title:        "Clé de sécurité",
		Nav:          "cles",
		User:         &user,
		CSRF:         csrfFrom(r),
		Sealed:       s.vault.Sealed(),
		Notice:       r.URL.Query().Get("info"),
		Error:        r.URL.Query().Get("erreur"),
		SecurityKeys: rows,
		HasCode:      hasCode,
	})
}

// startKeyRegistration poses the challenge for a new key.
func (s *Server) startKeyRegistration(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	rp := s.relyingParty(r)

	challenge, err := s.challenges.issue("register:"+user.ID, s.now())
	if err != nil {
		logError(r, err)
		refuse(w, http.StatusInternalServerError, "Erreur interne.")
		return
	}

	// The keys already registered are named so the browser can say "you have
	// already enrolled this one" instead of silently making a second
	// credential nobody can tell apart from the first.
	existing, err := s.vault.DB().SecurityKeys(r.Context(), user.ID)
	if err != nil {
		logError(r, err)
		refuse(w, http.StatusInternalServerError, "Erreur interne.")
		return
	}
	exclude := make([]credentialDescriptor, 0, len(existing))
	for _, key := range existing {
		exclude = append(exclude, credentialDescriptor{Type: "public-key", ID: encodeB64(key.CredentialID)})
	}

	writeJSON(w, http.StatusOK, registrationOptions{
		Challenge: encodeB64(challenge),
		RP:        map[string]string{"id": rp.RPID, "name": "SYNSEC"},
		User: map[string]string{
			"id":          encodeB64([]byte(user.ID)),
			"name":        user.Username,
			"displayName": user.DisplayName,
		},
		// The three algorithms this server can verify, most preferred first.
		PubKeyCredParams: []map[string]any{
			{"type": "public-key", "alg": -7},
			{"type": "public-key", "alg": -8},
			{"type": "public-key", "alg": -257},
		},
		Timeout:            int(challengeLife / time.Millisecond),
		ExcludeCredentials: exclude,
		AuthenticatorSelection: map[string]string{
			// No PIN asked for: the password was the first factor, and a key
			// that demands one as well turns a touch into a small ceremony.
			"userVerification": "discouraged",
			"residentKey":      "discouraged",
		},
		// Not requested, because it is not checked. Asking for a statement in
		// order to ignore it would only add a prompt on some browsers.
		Attestation: "none",
	})
}

// finishKeyRegistration checks the answer and stores the key.
func (s *Server) finishKeyRegistration(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	now := s.now()

	challenge, ok := s.challenges.take("register:"+user.ID, now)
	if !ok {
		refuse(w, http.StatusForbidden, "L'enregistrement a expiré. Recommence.")
		return
	}

	var given answer
	if err := json.Unmarshal([]byte(r.PostFormValue("credential")), &given); err != nil {
		refuse(w, http.StatusBadRequest, "Réponse illisible.")
		return
	}
	clientData, err1 := decodeB64(given.ClientDataJSON)
	attestation, err2 := decodeB64(given.AttestationObject)
	if err1 != nil || err2 != nil {
		refuse(w, http.StatusBadRequest, "Réponse illisible.")
		return
	}

	cred, err := webauthn.VerifyRegistration(s.relyingParty(r), challenge, clientData, attestation)
	if err != nil {
		logError(r, err)
		refuse(w, http.StatusBadRequest,
			"Cette clé n'a pas pu être vérifiée. Réessaie, ou essaie une autre clé.")
		return
	}

	key := store.SecurityKey{
		UserID:       user.ID,
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		AAGUID:       cred.AAGUID,
		SignCount:    cred.SignCount,
		Name:         keyName(r.PostFormValue("nom")),
	}
	if err := s.vault.DB().AddSecurityKey(r.Context(), &key, now); err != nil {
		if store.IsConstraintViolation(err) {
			refuse(w, http.StatusConflict, "Cette clé est déjà enregistrée.")
			return
		}
		logError(r, err)
		refuse(w, http.StatusInternalServerError, "Erreur interne.")
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "auth.key.add", Target: key.Name,
	})

	// A key on its own is a second factor with no way back: lose the object
	// and the account is shut. Recovery codes come with it.
	redirect, err := s.ensureRecoveryCodes(r.Context(), user, now)
	if err != nil {
		logError(r, err)
	}
	if redirect == "" {
		redirect = "/parametres/cles?info=" + urlEncode("Clé enregistrée.")
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": redirect})
}

// ensureRecoveryCodes mints a batch when the account has none, and returns the
// page that will show them. An empty string means there was nothing to do.
func (s *Server) ensureRecoveryCodes(ctx context.Context, user store.User, now time.Time) (string, error) {
	left, err := s.vault.DB().CountUnusedRecoveryCodes(ctx, user.ID)
	if err != nil || left > 0 {
		return "", err
	}

	codes, err := newRecoveryCodes()
	if err != nil {
		return "", err
	}
	stored := make([]string, len(codes))
	for i, code := range codes {
		stored[i] = normaliseRecovery(code)
	}

	// The account may or may not carry a code from an application; either way
	// the secret it already has must survive being given recovery codes.
	secret, err := s.vault.DB().TOTPSecret(ctx, user.ID)
	if err != nil {
		return "", err
	}
	if err := s.vault.DB().SetTOTPSecret(ctx, user.ID, secret, stored); err != nil {
		return "", err
	}

	s.freshCodes.put(user.ID, codes, now)
	return "/parametres/secours", nil
}

// showFreshRecoveryCodes displays a batch exactly once.
func (s *Server) showFreshRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)

	codes, ok := s.freshCodes.take(user.ID, s.now())
	if !ok {
		s.redirectWithNotice(w, r, "/parametres/cles",
			"Ces codes ont déjà été affichés. Pour en obtenir d'autres, désactive puis réactive la vérification en deux étapes.")
		return
	}

	s.render(w, r, "twofactor_codes.html", http.StatusOK, pageData{
		Title:         "Codes de secours",
		Nav:           "cles",
		User:          &user,
		CSRF:          csrfFrom(r),
		Sealed:        s.vault.Sealed(),
		RecoveryCodes: codes,
		Back:          "/parametres/cles",
	})
}

// removeSecurityKey forgets a key, against the account password.
//
// The password is asked for the same reason disabling the code is: a browser
// left open is exactly the situation the second factor exists to survive.
func (s *Server) removeSecurityKey(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	const back = "/parametres/cles"

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

	id := r.PostFormValue("id")
	keys, err := s.vault.DB().SecurityKeys(r.Context(), user.ID)
	if err != nil {
		s.fail(w, r, user, err)
		return
	}
	name := ""
	for _, key := range keys {
		if key.ID == id {
			name = key.Name
		}
	}

	// Removing the last factor on a server that insists on one would only
	// bounce this account into the enrolment page.
	if s.requiresFactor() && len(keys) == 1 {
		secret, err := s.vault.DB().TOTPSecret(r.Context(), user.ID)
		if err != nil {
			s.fail(w, r, user, err)
			return
		}
		if secret == "" {
			s.redirectWithError(w, r, back,
				"Ce serveur exige un second facteur. Enregistre une autre clé, ou active la vérification par code, avant de retirer celle-ci.")
			return
		}
	}

	if err := s.vault.DB().DeleteSecurityKey(r.Context(), user.ID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.redirectWithError(w, r, back, "Cette clé n'existe plus.")
			return
		}
		s.fail(w, r, user, err)
		return
	}

	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "auth.key.remove", Target: name,
	})
	s.redirectWithNotice(w, r, back, "Clé retirée.")
}

// startKeyAssertion poses the challenge for a sign-in that has passed the
// password and is now holding a key.
func (s *Server) startKeyAssertion(w http.ResponseWriter, r *http.Request) {
	limitBody(w, r)
	if err := r.ParseForm(); err != nil || !validLoginToken(r) {
		refuse(w, http.StatusForbidden, "Ce formulaire n'est plus valable. Recommence la connexion.")
		return
	}

	cookie, err := r.Cookie(pendingCookie)
	if err != nil || cookie.Value == "" {
		refuse(w, http.StatusForbidden, "Recommence la connexion.")
		return
	}
	userID, ok := s.readPendingToken(cookie.Value, s.now())
	if !ok {
		refuse(w, http.StatusForbidden, "La connexion a expiré. Recommence.")
		return
	}

	keys, err := s.vault.DB().SecurityKeys(r.Context(), userID)
	if err != nil {
		logError(r, err)
		refuse(w, http.StatusInternalServerError, "Erreur interne.")
		return
	}
	if len(keys) == 0 {
		refuse(w, http.StatusForbidden, "Aucune clé n'est enregistrée sur ce compte.")
		return
	}

	challenge, err := s.challenges.issue("login:"+userID, s.now())
	if err != nil {
		logError(r, err)
		refuse(w, http.StatusInternalServerError, "Erreur interne.")
		return
	}

	// Naming the credentials is what lets a key with no storage of its own -
	// most of them - work out which of its credentials this is.
	allow := make([]credentialDescriptor, 0, len(keys))
	for _, key := range keys {
		allow = append(allow, credentialDescriptor{Type: "public-key", ID: encodeB64(key.CredentialID)})
	}

	writeJSON(w, http.StatusOK, assertionOptions{
		Challenge:        encodeB64(challenge),
		RPID:             s.relyingParty(r).RPID,
		Timeout:          int(challengeLife / time.Millisecond),
		AllowCredentials: allow,
		UserVerification: "discouraged",
	})
}

// finishKeyAssertion checks the signature and, if it holds, signs the person in.
func (s *Server) finishKeyAssertion(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	limitBody(w, r)

	if err := r.ParseForm(); err != nil || !validLoginToken(r) {
		refuse(w, http.StatusForbidden, "Ce formulaire n'est plus valable. Recommence la connexion.")
		return
	}

	cookie, err := r.Cookie(pendingCookie)
	if err != nil || cookie.Value == "" {
		refuse(w, http.StatusForbidden, "Recommence la connexion.")
		return
	}
	userID, ok := s.readPendingToken(cookie.Value, now)
	if !ok {
		refuse(w, http.StatusForbidden, "La connexion a expiré. Recommence.")
		return
	}

	// The same throttle as the password and the code. A signature cannot be
	// guessed, but the work of checking one can still be asked for endlessly.
	throttleKey := s.clientIP(r)
	if wait, blocked := s.throttle.blocked(throttleKey, now); blocked {
		refuse(w, http.StatusTooManyRequests,
			"Trop de tentatives. Réessaie dans "+humanDuration(wait)+".")
		return
	}

	challenge, ok := s.challenges.take("login:"+userID, now)
	if !ok {
		refuse(w, http.StatusForbidden, "La demande a expiré. Réessaie.")
		return
	}

	var given answer
	if err := json.Unmarshal([]byte(r.PostFormValue("credential")), &given); err != nil {
		refuse(w, http.StatusBadRequest, "Réponse illisible.")
		return
	}
	credentialID, err1 := decodeB64(given.ID)
	clientData, err2 := decodeB64(given.ClientDataJSON)
	authData, err3 := decodeB64(given.AuthenticatorData)
	signature, err4 := decodeB64(given.Signature)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		refuse(w, http.StatusBadRequest, "Réponse illisible.")
		return
	}

	user, err := s.vault.DB().User(r.Context(), userID)
	if err != nil {
		s.clearPending(w)
		refuse(w, http.StatusForbidden, "Recommence la connexion.")
		return
	}

	key, err := s.vault.DB().SecurityKeyByCredential(r.Context(), credentialID)
	// Held to the account the password belongs to. Without this check, any
	// registered key on the server would open any account whose password had
	// just been given - which is not what a second factor is.
	if err != nil || key.UserID != userID {
		s.keyRefused(r, user, throttleKey, "clé inconnue")
		refuse(w, http.StatusUnauthorized, "Cette clé n'est pas enregistrée sur ce compte.")
		return
	}

	count, err := webauthn.VerifyAssertion(s.relyingParty(r), webauthn.Credential{
		ID:        key.CredentialID,
		PublicKey: key.PublicKey,
		SignCount: key.SignCount,
	}, challenge, clientData, authData, signature)
	if err != nil {
		logError(r, err)
		s.keyRefused(r, user, throttleKey, refusalDetail(err))
		refuse(w, http.StatusUnauthorized, "Cette clé n'a pas été acceptée.")
		return
	}

	if err := s.vault.DB().TouchSecurityKey(r.Context(), key.ID, count, now); err != nil {
		logError(r, err)
	}

	s.throttle.succeed(throttleKey)
	s.clearPending(w)

	if err := s.establishSession(w, r, user); err != nil {
		logError(r, err)
		refuse(w, http.StatusInternalServerError, "Erreur interne.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/"})
}

func (s *Server) keyRefused(r *http.Request, user store.User, throttleKey, detail string) {
	s.throttle.fail(throttleKey, s.now())
	s.audit(r, store.AuditEntry{
		ActorKind: store.ActorUser, ActorID: user.ID, ActorLabel: user.Username,
		Action: "auth.failed", Detail: "clé de sécurité refusée : " + detail,
	})
}

// refusalDetail turns a verification failure into a line the operator can act
// on. A cloned key is the one worth being able to find later.
func refusalDetail(err error) string {
	switch {
	case errors.Is(err, webauthn.ErrCloned):
		return "compteur en recul, clé possiblement dupliquée"
	case errors.Is(err, webauthn.ErrOrigin):
		return "origine ou domaine incorrect"
	case errors.Is(err, webauthn.ErrChallenge):
		return "réponse à un autre défi"
	default:
		return "signature invalide"
	}
}

// keyName settles on something readable for the list.
func keyName(given string) string {
	name := strings.TrimSpace(given)
	if name == "" {
		return "Clé de sécurité"
	}
	return truncate(name, 60)
}

// secondFactors reports what an account carries, which is what decides whether
// a password alone is still enough.
func (s *Server) secondFactors(ctx context.Context, userID string) (hasCode bool, keys int, err error) {
	secret, err := s.vault.DB().TOTPSecret(ctx, userID)
	if err != nil {
		return false, 0, err
	}
	keys, err = s.vault.DB().CountSecurityKeys(ctx, userID)
	if err != nil {
		return false, 0, err
	}
	return secret != "", keys, nil
}
