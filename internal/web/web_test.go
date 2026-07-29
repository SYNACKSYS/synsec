package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"synsec/internal/auth"
	"synsec/internal/crypto"
	"synsec/internal/store"
	"synsec/internal/vault"
)

const testPassword = "correct horse battery"

type harness struct {
	srv     *httptest.Server
	manager *vault.Manager
	client  *http.Client
}

// newHarness builds a server over a throwaway database. Options are appended
// to the ones every test needs, so a test can pin the clock or the idle
// timeout without restating the rest.
func newHarness(t *testing.T, opts ...Option) *harness {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	db, err := store.Open(filepath.Join(dir, "synsec.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	m := vault.New(db, dir)
	if _, err := m.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	t.Cleanup(m.Seal)

	// A light Argon2 profile: these tests sign in repeatedly and the default
	// 64 MiB cost would dominate the run.
	cred, err := auth.HashPasswordWith(testPassword, crypto.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1})
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	// The first account, as the command line would create it: administrator
	// and holder of the journal.
	u := store.User{Username: "cyril", DisplayName: "Cyril", IsAdmin: true, IsRoot: true}
	if err := db.CreateUser(ctx, &u, cred); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// The test server speaks plain HTTP, so a Secure cookie would be dropped.
	ui, err := New(m, append([]Option{insecureCookies()}, opts...)...)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	srv := httptest.NewServer(ui.Handler())
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		// Redirects are inspected rather than followed, so a test can assert
		// where the server sent the browser.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &harness{srv: srv, manager: m, client: client}
}

func (h *harness) get(t *testing.T, path string) *http.Response {
	t.Helper()
	resp, err := h.client.Get(h.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (h *harness) post(t *testing.T, path string, form url.Values) *http.Response {
	t.Helper()
	resp, err := h.client.PostForm(h.srv.URL+path, form)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// loginToken fetches the sign-in page and returns the token it set, the way a
// browser would before submitting the form.
func (h *harness) loginToken(t *testing.T) string {
	t.Helper()
	h.get(t, "/login")

	u, err := url.Parse(h.srv.URL + "/login")
	if err != nil {
		t.Fatalf("parsing server URL: %v", err)
	}
	for _, c := range h.client.Jar.Cookies(u) {
		if c.Name == loginCookie {
			return c.Value
		}
	}
	t.Fatal("the sign-in page set no login token")
	return ""
}

func (h *harness) signIn(t *testing.T) {
	t.Helper()
	resp := h.post(t, "/login", url.Values{
		"login_csrf": {h.loginToken(t)},
		"username":   {"cyril"},
		"password":   {testPassword},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign-in returned %d, want 303", resp.StatusCode)
	}
}

// sessionCookieValue returns the cookie the jar is holding, so a test can
// derive the CSRF token the same way the server does.
func (h *harness) sessionCookieValue(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(h.srv.URL)
	if err != nil {
		t.Fatalf("parsing server URL: %v", err)
	}
	for _, c := range h.client.Jar.Cookies(u) {
		if c.Name == sessionCookie {
			return c.Value
		}
	}
	return ""
}

// withoutLoginToken blanks the per-render sign-in token, so two pages can be
// compared for everything else.
func withoutLoginToken(page string) string {
	const marker = `name="login_csrf" value="`
	start := strings.Index(page, marker)
	if start < 0 {
		return page
	}
	rest := page[start+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return page
	}
	return page[:start+len(marker)] + rest[end:]
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return string(b)
}

func TestHomeRequiresSignIn(t *testing.T) {
	h := newHarness(t)

	resp := h.get(t, "/")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("the home page returned %d to an anonymous visitor, want a redirect", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("redirected to %q, want /login", loc)
	}
}

func TestSignInAndOut(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	resp := h.get(t, "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the home page returned %d after signing in", resp.StatusCode)
	}
	if page := body(t, resp); !strings.Contains(page, "Cyril") {
		t.Fatal("the home page does not show who is signed in")
	}

	csrf := csrfToken(h.sessionCookieValue(t))
	resp = h.post(t, "/logout", url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("signing out returned %d", resp.StatusCode)
	}

	if resp := h.get(t, "/"); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("the session survived signing out")
	}
}

// A wrong password and an unknown account must be indistinguishable, or
// anyone can find out which accounts exist.
func TestFailedSignInsLookIdentical(t *testing.T) {
	h := newHarness(t)

	wrongPassword := h.post(t, "/login", url.Values{
		"login_csrf": {h.loginToken(t)},
		"username":   {"cyril"}, "password": {"pas le bon"},
	})
	unknownUser := h.post(t, "/login", url.Values{
		"login_csrf": {h.loginToken(t)},
		"username":   {"personne"}, "password": {testPassword},
	})

	if wrongPassword.StatusCode != unknownUser.StatusCode {
		t.Fatalf("wrong password gives %d, unknown account gives %d",
			wrongPassword.StatusCode, unknownUser.StatusCode)
	}
	// Each refusal carries a fresh sign-in token, so the pages differ by that
	// one value and by nothing else - which is what has to be compared.
	if withoutLoginToken(body(t, wrongPassword)) != withoutLoginToken(body(t, unknownUser)) {
		t.Fatal("the two failures produce different pages")
	}
}

func TestSignInRejectsBadCredentials(t *testing.T) {
	h := newHarness(t)

	resp := h.post(t, "/login", url.Values{
		"login_csrf": {h.loginToken(t)},
		"username":   {"cyril"}, "password": {"pas le bon"},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong password returned %d, want 401", resp.StatusCode)
	}
	if h.sessionCookieValue(t) != "" {
		t.Fatal("a failed sign-in still set a session cookie")
	}
}

// Without a CSRF token, another site could sign the owner out - and, once the
// interface can write, do a great deal worse.
func TestPostsWithoutCSRFAreRefused(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)

	resp := h.post(t, "/logout", url.Values{})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a form without a CSRF token returned %d, want 403", resp.StatusCode)
	}
	resp = h.post(t, "/logout", url.Values{"csrf": {"n'importe quoi"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a form with a wrong CSRF token returned %d, want 403", resp.StatusCode)
	}

	// The session must survive a refused request.
	if resp := h.get(t, "/"); resp.StatusCode != http.StatusOK {
		t.Fatal("a refused form ended the session")
	}
}

// The CSRF token is derived from the session, so one session's token must not
// work for another.
func TestCSRFTokenIsTiedToItsSession(t *testing.T) {
	a := csrfToken("session-a")
	b := csrfToken("session-b")

	if a == b {
		t.Fatal("two different sessions derive the same CSRF token")
	}
	if a != csrfToken("session-a") {
		t.Fatal("the same session derives two different CSRF tokens")
	}
	if a == "" {
		t.Fatal("the derived CSRF token is empty")
	}
}

func TestSessionCookieIsProtected(t *testing.T) {
	h := newHarness(t)

	resp := h.post(t, "/login", url.Values{
		"login_csrf": {h.loginToken(t)},
		"username":   {"cyril"}, "password": {testPassword},
	})

	var found bool
	for _, c := range resp.Cookies() {
		if c.Name != sessionCookie {
			continue
		}
		found = true
		if !c.HttpOnly {
			t.Error("the session cookie is readable by scripts")
		}
		if c.SameSite != http.SameSiteStrictMode {
			t.Error("the session cookie is not SameSite=Strict")
		}
	}
	if !found {
		t.Fatal("signing in set no session cookie")
	}
}

func TestSignInIsThrottled(t *testing.T) {
	h := newHarness(t)

	var last *http.Response
	for i := 0; i < throttleAfter+1; i++ {
		last = h.post(t, "/login", url.Values{
			"login_csrf": {h.loginToken(t)},
			"username":   {"cyril"}, "password": {"pas le bon"},
		})
	}
	if last.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("repeated failures returned %d, want 429", last.StatusCode)
	}

	// The lockout must hold even once the password is right, or it would
	// achieve nothing.
	resp := h.post(t, "/login", url.Values{
		"login_csrf": {h.loginToken(t)},
		"username":   {"cyril"}, "password": {testPassword},
	})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a correct password bypassed the lockout (%d)", resp.StatusCode)
	}
}

func TestThrottleForgetsAfterSuccess(t *testing.T) {
	th := newThrottle()
	now := time.Now()

	for i := 0; i < throttleAfter-1; i++ {
		th.fail("192.168.1.10", now)
	}
	if _, blocked := th.blocked("192.168.1.10", now); blocked {
		t.Fatal("locked out before reaching the threshold")
	}

	th.fail("192.168.1.10", now)
	if _, blocked := th.blocked("192.168.1.10", now); !blocked {
		t.Fatal("not locked out at the threshold")
	}

	th.succeed("192.168.1.10")
	if _, blocked := th.blocked("192.168.1.10", now); blocked {
		t.Fatal("the lockout survived a correct password")
	}
}

func TestSignInIsAudited(t *testing.T) {
	h := newHarness(t)
	h.post(t, "/login", url.Values{
		"login_csrf": {h.loginToken(t)},
		"username":   {"cyril"}, "password": {"pas le bon"},
	})
	h.signIn(t)

	entries, err := h.manager.DB().ListAudit(context.Background(), store.AuditFilter{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}

	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		seen[e.Action] = true
		if strings.Contains(e.Detail, testPassword) {
			t.Fatal("the audit log recorded a password")
		}
	}
	for _, action := range []string{"auth.failed", "auth.signin"} {
		if !seen[action] {
			t.Fatalf("%s was not recorded; log holds %v", action, seen)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t)
	resp := h.get(t, "/login")

	for header, want := range map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "no-store",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s is %q, want %q", header, got, want)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("the content security policy is %q", csp)
	}
}

func TestStaticAssetsAreEmbedded(t *testing.T) {
	h := newHarness(t)

	resp := h.get(t, "/static/style.css")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the stylesheet returned %d", resp.StatusCode)
	}
	if !strings.Contains(body(t, resp), "--accent") {
		t.Fatal("the stylesheet served is not the embedded one")
	}

	if _, err := staticFS(); err != nil {
		t.Fatalf("the embedded assets are unreadable: %v", err)
	}
}

func TestTemplatesAllParse(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatalf("parsePages: %v", err)
	}
	for _, name := range pageNames {
		if _, ok := pages[name]; !ok {
			t.Errorf("%s was not parsed", name)
		}
	}
}

// The browser is told never to try plain HTTP again: SYNSEC has no such mode,
// and the first request typed without a scheme goes out in clear.
func TestWebSetsStrictTransportSecurity(t *testing.T) {
	h := newHarness(t)

	resp := h.get(t, "/login")
	if got := resp.Header.Get("Strict-Transport-Security"); got == "" {
		t.Fatal("no Strict-Transport-Security header on the sign-in page")
	}

	h.signIn(t)
	resp = h.get(t, "/")
	if got := resp.Header.Get("Strict-Transport-Security"); got == "" {
		t.Fatal("no Strict-Transport-Security header once signed in")
	}
}

// The throttle keeps one record per address that has failed. Without a sweep
// the table only ever grows, and a spray from many sources becomes a way to
// exhaust a small machine's memory at no cost to the sender.
func TestTheThrottleForgetsQuietAddresses(t *testing.T) {
	th := newThrottle()
	now := time.Now()

	for i := 0; i < 500; i++ {
		th.fail(fmt.Sprintf("192.0.2.%d", i), now)
	}
	if len(th.records) != 500 {
		t.Fatalf("%d records held, want 500", len(th.records))
	}

	// An hour later a single new address arrives; the rest are long past
	// anything their history could mean.
	th.fail("198.51.100.1", now.Add(throttleForget+time.Minute))
	if len(th.records) != 1 {
		t.Fatalf("%d records survived the sweep, want 1", len(th.records))
	}
}

// An address serving out its lockout must never be forgotten early, or the
// sweep would become the way around the throttle.
func TestALockedAddressIsNotSweptAway(t *testing.T) {
	th := newThrottle()
	now := time.Now()

	for i := 0; i < throttleAfter; i++ {
		th.fail("192.0.2.10", now)
	}
	if _, blocked := th.blocked("192.0.2.10", now); !blocked {
		t.Fatal("the address was not locked out")
	}

	// Someone else arrives while the lockout still runs. Half a minute in,
	// because five failures buy exactly one minute and the point is to look
	// while it is still running, not at the instant it ends.
	th.fail("198.51.100.1", now.Add(30*time.Second))
	if _, blocked := th.blocked("192.0.2.10", now.Add(30*time.Second)); !blocked {
		t.Fatal("the sweep released an address still serving its lockout")
	}
}
