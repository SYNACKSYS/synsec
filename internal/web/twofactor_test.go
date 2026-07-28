package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"synsec/internal/auth"
)

// codeFor is what the authenticator would show right now.
func codeFor(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	code, err := auth.TOTPCodeAt(secret, now)
	if err != nil {
		t.Fatalf("TOTPCodeAt: %v", err)
	}
	return code
}

// passwordStep signs in as far as the password takes it. With a second factor
// on the account, that is the verification page rather than a session.
func (h *harness) passwordStep(t *testing.T, username string) {
	t.Helper()
	h.newJar(t)

	resp := h.post(t, "/login", url.Values{
		"login_csrf": {h.loginToken(t)},
		"username":   {username},
		"password":   {testPassword},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the password step returned %d, want the verification page", resp.StatusCode)
	}
}

// enable turns the second factor on for the signed-in account and returns the
// secret and the recovery codes.
func (h *harness) enableTwoFactor(t *testing.T) (string, []string) {
	t.Helper()

	page := body(t, h.get(t, "/parametres/verification"))
	const marker = `name="secret" value="`
	start := strings.Index(page, marker)
	if start < 0 {
		t.Fatal("the enrolment page offers no secret")
	}
	rest := page[start+len(marker):]
	secret := rest[:strings.Index(rest, `"`)]

	resp := h.post(t, "/parametres/verification", url.Values{
		"csrf": {h.csrf(t)}, "secret": {secret},
		"code": {codeFor(t, secret, time.Now())},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enabling returned %d", resp.StatusCode)
	}

	codesPage := body(t, resp)
	var codes []string
	for _, line := range strings.Split(codesPage, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 11 && strings.Count(line, "-") == 1 {
			codes = append(codes, line)
		}
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("%d recovery codes were shown, want %d", len(codes), recoveryCodeCount)
	}
	return secret, codes
}

// A password alone must stop being enough the moment a second factor is on.
func TestSecondFactorIsRequiredAfterThePassword(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	secret, _ := h.enableTwoFactor(t)

	h.passwordStep(t, "cyril")
	if resp := h.get(t, "/"); resp.StatusCode == http.StatusOK {
		t.Fatal("the password alone opened a session")
	}

	resp := h.post(t, "/login/code", url.Values{
		"login_csrf": {h.loginToken(t)},
		"code":       {codeFor(t, secret, time.Now())},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a valid code returned %d, want 303", resp.StatusCode)
	}
	if resp := h.get(t, "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the session was not created after the code (%d)", resp.StatusCode)
	}
}

func TestWrongCodeDoesNotOpenASession(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	h.enableTwoFactor(t)

	h.passwordStep(t, "cyril")
	resp := h.post(t, "/login/code", url.Values{
		"login_csrf": {h.loginToken(t)}, "code": {"000000"},
	})
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("a wrong code opened a session")
	}
	if resp := h.get(t, "/"); resp.StatusCode == http.StatusOK {
		t.Fatal("the session exists despite the wrong code")
	}
}

// A lost phone must not mean a lost account, and a code must work once.
func TestRecoveryCodeWorksOnceOnly(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	_, codes := h.enableTwoFactor(t)
	ctx := context.Background()

	h.passwordStep(t, "cyril")
	resp := h.post(t, "/login/code", url.Values{
		"login_csrf": {h.loginToken(t)}, "code": {codes[0]},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a recovery code returned %d, want 303", resp.StatusCode)
	}

	left, err := h.manager.DB().CountUnusedRecoveryCodes(ctx, h.userID(t, "cyril"))
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if left != recoveryCodeCount-1 {
		t.Fatalf("%d codes left, want %d", left, recoveryCodeCount-1)
	}

	// The same code must not open a second session.
	h.passwordStep(t, "cyril")
	resp = h.post(t, "/login/code", url.Values{
		"login_csrf": {h.loginToken(t)}, "code": {codes[0]},
	})
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("a spent recovery code worked a second time")
	}
}

// Turning it off is held to the password, because a browser left open is the
// situation the second factor exists to survive.
func TestDisablingNeedsThePassword(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	h.enableTwoFactor(t)
	ctx := context.Background()

	resp := h.post(t, "/parametres/verification/desactiver", url.Values{
		"csrf": {h.csrf(t)}, "password": {"pas le bon"},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("a wrong password disabled the second factor: %q", loc)
	}
	if secret, _ := h.manager.DB().TOTPSecret(ctx, h.userID(t, "cyril")); secret == "" {
		t.Fatal("the second factor was turned off anyway")
	}

	h.post(t, "/parametres/verification/desactiver", url.Values{
		"csrf": {h.csrf(t)}, "password": {testPassword},
	})
	if secret, _ := h.manager.DB().TOTPSecret(ctx, h.userID(t, "cyril")); secret != "" {
		t.Fatal("the correct password did not turn it off")
	}
}

// Nothing is stored until a code proves the application holds the secret, or
// enrolling would lock the account out at the next sign-in.
func TestEnrolmentNeedsAValidCode(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx := context.Background()

	page := body(t, h.get(t, "/parametres/verification"))
	const marker = `name="secret" value="`
	start := strings.Index(page, marker)
	rest := page[start+len(marker):]
	secret := rest[:strings.Index(rest, `"`)]

	resp := h.post(t, "/parametres/verification", url.Values{
		"csrf": {h.csrf(t)}, "secret": {secret}, "code": {"000000"},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("a wrong code enrolled the account: %q", loc)
	}
	if stored, _ := h.manager.DB().TOTPSecret(ctx, h.userID(t, "cyril")); stored != "" {
		t.Fatal("the secret was stored without a valid code")
	}
}

func (h *harness) userID(t *testing.T, username string) string {
	t.Helper()
	u, err := h.manager.DB().UserByUsername(context.Background(), username)
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	return u.ID
}
