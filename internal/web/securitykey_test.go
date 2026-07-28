package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The tests below play the browser and the key at once: they ask the server
// for a challenge, compose the bytes a real authenticator would return, sign
// them, and post the answer. What is being checked here is the wiring - the
// challenge, the account a credential belongs to, the session that comes out -
// rather than the arithmetic, which the webauthn package covers on its own.

// fakeKey is a P-256 key pair standing in for the object in the drawer.
type fakeKey struct {
	priv         *ecdsa.PrivateKey
	credentialID []byte
}

func newFakeKey(t *testing.T, credentialID string) *fakeKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &fakeKey{priv: priv, credentialID: []byte(credentialID)}
}

// A CBOR writer, only as much as an authenticator's answer needs.

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	default:
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	}
}

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }

func cborMap(pairs ...[]byte) []byte {
	out := cborHead(5, uint64(len(pairs)/2))
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}

func (k *fakeKey) cose() []byte {
	x := k.priv.PublicKey.X.FillBytes(make([]byte, 32))
	y := k.priv.PublicKey.Y.FillBytes(make([]byte, 32))

	return cborMap(
		cborHead(0, 1), cborHead(0, 2), // kty: EC2
		cborHead(0, 3), cborHead(1, 6), // alg: ES256
		cborHead(1, 0), cborHead(0, 1), // crv: P-256
		cborHead(1, 1), cborBytes(x),
		cborHead(1, 2), cborBytes(y),
	)
}

func (k *fakeKey) authData(rpID string, flags byte, count uint32, withCredential bool) []byte {
	hash := sha256.Sum256([]byte(rpID))

	out := append([]byte(nil), hash[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, count)
	if !withCredential {
		return out
	}

	out = append(out, make([]byte, 16)...) // AAGUID
	out = binary.BigEndian.AppendUint16(out, uint16(len(k.credentialID)))
	out = append(out, k.credentialID...)
	return append(out, k.cose()...)
}

func (k *fakeKey) sign(t *testing.T, message []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, sum[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return sig
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// host is the name the test server answers to, which is what the ceremonies
// are scoped to.
func (h *harness) host(t *testing.T) (rpID, origin string) {
	t.Helper()
	u, err := url.Parse(h.srv.URL)
	if err != nil {
		t.Fatalf("parsing server URL: %v", err)
	}
	return u.Hostname(), h.srv.URL
}

func clientJSON(kind string, challenge []byte, origin string) []byte {
	body, _ := json.Marshal(map[string]any{
		"type":        kind,
		"challenge":   b64(challenge),
		"origin":      origin,
		"crossOrigin": false,
	})
	return body
}

// jsonBody decodes a scripted reply.
func jsonBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(body(t, resp)), &out); err != nil {
		t.Fatalf("the reply is not JSON: %v", err)
	}
	return out
}

// registerKey runs the enrolment the way the script does, and returns the
// response the server gave to the second half.
func (h *harness) registerKey(t *testing.T, key *fakeKey, name string) *http.Response {
	t.Helper()
	rpID, origin := h.host(t)

	options := jsonBody(t, h.post(t, "/parametres/cles/defi", url.Values{"csrf": {h.csrf(t)}}))
	challenge, err := base64.RawURLEncoding.DecodeString(options["challenge"].(string))
	if err != nil {
		t.Fatalf("the challenge is not base64url: %v", err)
	}

	answer, _ := json.Marshal(map[string]string{
		"id":             b64(key.credentialID),
		"clientDataJSON": b64(clientJSON("webauthn.create", challenge, origin)),
		"attestationObject": b64(cborMap(
			cborText("fmt"), cborText("none"),
			cborText("attStmt"), cborMap(),
			cborText("authData"), cborBytes(key.authData(rpID, 0x01|0x40, 0, true)),
		)),
	})

	return h.post(t, "/parametres/cles", url.Values{
		"csrf": {h.csrf(t)}, "nom": {name}, "credential": {string(answer)},
	})
}

// answerWithKey runs the sign-in half: the password has been given, the key
// now answers the challenge.
func (h *harness) answerWithKey(t *testing.T, key *fakeKey, count uint32) *http.Response {
	t.Helper()
	rpID, origin := h.host(t)

	token := h.loginToken(t)
	options := jsonBody(t, h.post(t, "/login/cle/defi", url.Values{"login_csrf": {token}}))
	raw, ok := options["challenge"].(string)
	if !ok {
		t.Fatalf("no challenge in the reply: %v", options)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("the challenge is not base64url: %v", err)
	}

	client := clientJSON("webauthn.get", challenge, origin)
	authData := key.authData(rpID, 0x01, count, false)
	sum := sha256.Sum256(client)

	answer, _ := json.Marshal(map[string]string{
		"id":                b64(key.credentialID),
		"clientDataJSON":    b64(client),
		"authenticatorData": b64(authData),
		"signature":         b64(key.sign(t, append(append([]byte(nil), authData...), sum[:]...))),
	})

	return h.post(t, "/login/cle", url.Values{
		"login_csrf": {token}, "credential": {string(answer)},
	})
}

// The whole point: a key registered on an account signs it in afterwards.
func TestASecurityKeySignsIn(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	key := newFakeKey(t, "cle-du-trousseau")
	if resp := h.registerKey(t, key, "YubiKey bleue"); resp.StatusCode != http.StatusOK {
		t.Fatalf("registering returned %d: %s", resp.StatusCode, body(t, resp))
	}

	// The password alone must now stop short of a session.
	h.passwordStep(t, "cyril")
	if resp := h.get(t, "/"); resp.StatusCode == http.StatusOK {
		t.Fatal("the password alone opened a session")
	}

	resp := h.answerWithKey(t, key, 1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the key returned %d: %s", resp.StatusCode, body(t, resp))
	}
	if resp := h.get(t, "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the session was not created after the key (%d)", resp.StatusCode)
	}
}

// A key belongs to one account. Without that check, any registered key would
// open any account whose password had just been given.
func TestAKeyDoesNotOpenAnotherAccount(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	key := newFakeKey(t, "la-cle-de-cyril")
	h.registerKey(t, key, "clé de Cyril")

	// Alice has her own key, so the sign-in offers the ceremony; she answers
	// with Cyril's.
	h.addUser(t, "alice")
	h.signInAs(t, "alice")
	h.registerKey(t, newFakeKey(t, "la-cle-d-alice"), "clé d'Alice")

	h.passwordStep(t, "alice")
	resp := h.answerWithKey(t, key, 1)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("another account's key opened this one")
	}
	if resp := h.get(t, "/"); resp.StatusCode == http.StatusOK {
		t.Fatal("a session exists despite the wrong key")
	}
}

// A challenge answered once must not be answerable again, or a captured
// ceremony would work for as long as the page was open.
func TestAChallengeIsSpentByItsAnswer(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	key := newFakeKey(t, "cle")
	h.registerKey(t, key, "clé")

	h.passwordStep(t, "cyril")
	rpID, origin := h.host(t)

	token := h.loginToken(t)
	options := jsonBody(t, h.post(t, "/login/cle/defi", url.Values{"login_csrf": {token}}))
	challenge, _ := base64.RawURLEncoding.DecodeString(options["challenge"].(string))

	client := clientJSON("webauthn.get", challenge, origin)
	authData := key.authData(rpID, 0x01, 1, false)
	sum := sha256.Sum256(client)
	answer, _ := json.Marshal(map[string]string{
		"id":                b64(key.credentialID),
		"clientDataJSON":    b64(client),
		"authenticatorData": b64(authData),
		"signature":         b64(key.sign(t, append(append([]byte(nil), authData...), sum[:]...))),
	})

	form := url.Values{"login_csrf": {token}, "credential": {string(answer)}}
	if resp := h.post(t, "/login/cle", form); resp.StatusCode != http.StatusOK {
		t.Fatalf("the first answer returned %d", resp.StatusCode)
	}

	// The very same bytes, replayed.
	h.newJar(t)
	h.passwordStep(t, "cyril")
	if resp := h.post(t, "/login/cle", form); resp.StatusCode == http.StatusOK {
		t.Fatal("a replayed answer was accepted")
	}
}

// A key on its own is a second factor with no way back, so registering the
// first one has to hand over recovery codes.
func TestTheFirstKeyComesWithRecoveryCodes(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	resp := h.registerKey(t, newFakeKey(t, "cle"), "clé")
	reply := jsonBody(t, resp)
	if reply["redirect"] != "/parametres/secours" {
		t.Fatalf("registering sent the browser to %v, want the recovery codes", reply["redirect"])
	}

	page := body(t, h.get(t, "/parametres/secours"))
	var codes int
	for _, line := range strings.Split(page, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 11 && strings.Count(line, "-") == 1 {
			codes++
		}
	}
	if codes != recoveryCodeCount {
		t.Fatalf("%d recovery codes were shown, want %d", codes, recoveryCodeCount)
	}

	left, err := h.manager.DB().CountUnusedRecoveryCodes(context.Background(), h.userID(t, "cyril"))
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if left != recoveryCodeCount {
		t.Fatalf("%d codes are stored, want %d", left, recoveryCodeCount)
	}

	// Shown once. A second visit must not repeat them.
	if again := h.get(t, "/parametres/secours"); again.StatusCode != http.StatusSeeOther {
		t.Fatal("the recovery codes were shown a second time")
	}
}

// The way back in when the key is lost.
func TestARecoveryCodeWorksWithoutAnApplication(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	h.registerKey(t, newFakeKey(t, "cle"), "clé")

	page := body(t, h.get(t, "/parametres/secours"))
	var codes []string
	for _, line := range strings.Split(page, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 11 && strings.Count(line, "-") == 1 {
			codes = append(codes, line)
		}
	}
	if len(codes) == 0 {
		t.Fatal("no recovery codes were shown")
	}

	h.passwordStep(t, "cyril")
	resp := h.post(t, "/login/code", url.Values{
		"login_csrf": {h.loginToken(t)}, "code": {codes[0]},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a recovery code returned %d, want 303", resp.StatusCode)
	}
}

// Removing a factor is held to the password, because a browser left open is
// the situation the key exists to survive.
func TestRemovingAKeyNeedsThePassword(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	h.registerKey(t, newFakeKey(t, "cle"), "clé")
	ctx := context.Background()

	keys, err := h.manager.DB().SecurityKeys(ctx, h.userID(t, "cyril"))
	if err != nil || len(keys) != 1 {
		t.Fatalf("SecurityKeys returned %d keys (%v)", len(keys), err)
	}

	resp := h.post(t, "/parametres/cles/retirer", url.Values{
		"csrf": {h.csrf(t)}, "id": {keys[0].ID}, "password": {"pas le bon"},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("a wrong password removed the key: %q", loc)
	}
	if n, _ := h.manager.DB().CountSecurityKeys(ctx, h.userID(t, "cyril")); n != 1 {
		t.Fatal("the key was removed anyway")
	}

	h.post(t, "/parametres/cles/retirer", url.Values{
		"csrf": {h.csrf(t)}, "id": {keys[0].ID}, "password": {testPassword},
	})
	if n, _ := h.manager.DB().CountSecurityKeys(ctx, h.userID(t, "cyril")); n != 0 {
		t.Fatal("the correct password did not remove the key")
	}
}

// Turning off the application must not take the recovery codes with it when a
// key is still there: those codes are what reopens the account if it is lost.
func TestDisablingTheApplicationKeepsTheCodesWhenAKeyRemains(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	h.enableTwoFactor(t)
	h.registerKey(t, newFakeKey(t, "cle"), "clé")
	ctx := context.Background()

	h.post(t, "/parametres/verification/desactiver", url.Values{
		"csrf": {h.csrf(t)}, "password": {testPassword},
	})

	userID := h.userID(t, "cyril")
	if secret, _ := h.manager.DB().TOTPSecret(ctx, userID); secret != "" {
		t.Fatal("the application secret survived")
	}
	left, err := h.manager.DB().CountUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if left != recoveryCodeCount {
		t.Fatalf("%d recovery codes left, want %d - the key has no way back", left, recoveryCodeCount)
	}
}

// The credential identifiers are what the browser needs to find the right key.
// They are handed out only after the password, so the sign-in page never says
// whether an account exists or what it carries.
func TestTheChallengeIsRefusedWithoutThePassword(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	h.registerKey(t, newFakeKey(t, "cle"), "clé")

	h.newJar(t)
	resp := h.post(t, "/login/cle/defi", url.Values{"login_csrf": {h.loginToken(t)}})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a challenge was handed out before the password")
	}
}

// The server-wide requirement.

// Signing in still works - there would be no way to enrol otherwise - but the
// session reaches the enrolment pages and nothing else.
func TestARequiredFactorLocksTheInterfaceUntilEnrolled(t *testing.T) {
	h := newHarness(t, RequireSecondFactor(true))
	h.signIn(t)

	for _, path := range []string{"/", "/coffres/nouveau", "/comptes", "/journal", "/parametres"} {
		resp := h.get(t, path)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("%s returned %d, want a diversion to the enrolment page", path, resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/parametres/verification") {
			t.Fatalf("%s sent the browser to %q", path, loc)
		}
	}

	// The two ways out must stay open, and say why they are the only ones.
	page := body(t, h.get(t, "/parametres/verification?enrolement=1"))
	if !strings.Contains(page, "exige un second facteur") {
		t.Fatal("the enrolment page does not say the server requires a factor")
	}
	if resp := h.get(t, "/parametres/cles"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the security key page returned %d during enrolment", resp.StatusCode)
	}
}

// Writing must be diverted like reading: a form posted from a tab left open
// before the policy came on must not go through.
func TestARequiredFactorDivertsWritesToo(t *testing.T) {
	h := newHarness(t, RequireSecondFactor(true))
	h.signIn(t)
	ctx := context.Background()

	resp := h.post(t, "/coffres", url.Values{
		"csrf": {h.csrf(t)}, "name": {"Maison"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("creating a vault returned %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/parametres/verification") {
		t.Fatalf("the write was not diverted: %q", loc)
	}

	vaults, err := h.manager.DB().ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(vaults) != 0 {
		t.Fatal("the vault was created despite the missing factor")
	}
}

// Enrolling - by either route - lifts the diversion.
func TestEnrollingLiftsTheRequirement(t *testing.T) {
	h := newHarness(t, RequireSecondFactor(true))
	h.signIn(t)

	h.registerKey(t, newFakeKey(t, "cle"), "clé")
	if resp := h.get(t, "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the home page still returned %d after enrolling a key", resp.StatusCode)
	}
}

func TestEnrollingAnApplicationAlsoLiftsIt(t *testing.T) {
	h := newHarness(t, RequireSecondFactor(true))
	h.signIn(t)

	h.enableTwoFactor(t)
	if resp := h.get(t, "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the home page still returned %d after enrolling an application", resp.StatusCode)
	}
}

// Turning off the last factor would only bounce the account back into
// enrolment, so it is refused with a reason instead.
func TestTheLastFactorCannotBeRemovedUnderThePolicy(t *testing.T) {
	h := newHarness(t, RequireSecondFactor(true))
	h.signIn(t)
	h.enableTwoFactor(t)
	ctx := context.Background()

	resp := h.post(t, "/parametres/verification/desactiver", url.Values{
		"csrf": {h.csrf(t)}, "password": {testPassword},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("the last factor was removed: %q", loc)
	}
	if secret, _ := h.manager.DB().TOTPSecret(ctx, h.userID(t, "cyril")); secret == "" {
		t.Fatal("the application was disabled anyway")
	}

	// With a key alongside it, the application may go.
	h.registerKey(t, newFakeKey(t, "cle"), "clé")
	h.post(t, "/parametres/verification/desactiver", url.Values{
		"csrf": {h.csrf(t)}, "password": {testPassword},
	})
	if secret, _ := h.manager.DB().TOTPSecret(ctx, h.userID(t, "cyril")); secret != "" {
		t.Fatal("the application survived even with a key in place")
	}

	// And now the key is the last factor, so it is the one that is held.
	keys, _ := h.manager.DB().SecurityKeys(ctx, h.userID(t, "cyril"))
	resp = h.post(t, "/parametres/cles/retirer", url.Values{
		"csrf": {h.csrf(t)}, "id": {keys[0].ID}, "password": {testPassword},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("the last key was removed: %q", loc)
	}
	if n, _ := h.manager.DB().CountSecurityKeys(ctx, h.userID(t, "cyril")); n != 1 {
		t.Fatal("the account was left with no factor at all")
	}
}

// Off by default: a household where one forgotten phone locks somebody out is
// a worse outcome than the risk the setting removes.
func TestWithoutThePolicyAPasswordStillOpensTheInterface(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	if resp := h.get(t, "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the home page returned %d without any policy", resp.StatusCode)
	}
}
