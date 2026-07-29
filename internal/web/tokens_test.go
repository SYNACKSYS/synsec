package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"synsec/internal/auth"
	"synsec/internal/store"
)

func TestDevicesPageIsManagerOnly(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	alice := h.addUser(t, "alice")
	ctx := context.Background()

	h.manager.DB().SetVaultMember(ctx, vault.ID, alice.ID, store.RoleWriter, "cyril")
	h.signInAs(t, "alice")

	if resp := h.get(t, "/coffres/"+vault.ID+"/appareils"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a writer reached the devices page (%d)", resp.StatusCode)
	}
	resp := h.post(t, "/coffres/"+vault.ID+"/appareils", url.Values{
		"csrf": {h.csrf(t)}, "name": {"Pirate"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a writer minted a token (%d)", resp.StatusCode)
	}

	tokens, _ := h.manager.DB().ListServiceTokens(ctx, vault.ID)
	if len(tokens) != 0 {
		t.Fatalf("%d tokens were created", len(tokens))
	}
}

// The plaintext exists for one response and must never travel in a URL, where
// it would land in the browser history and in any proxy log on the way.
func TestNewTokenIsShownOnceAndNotRedirected(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	resp := h.post(t, "/coffres/"+vault.ID+"/appareils", url.Values{
		"csrf": {h.csrf(t)}, "name": {"Home Assistant"}, "expires": {"0"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("creating a token returned %d, want the page itself", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("the token was carried through a redirect to %q", loc)
	}

	page := body(t, resp)
	start := strings.Index(page, "syn_")
	if start < 0 {
		t.Fatal("the page does not show the token")
	}

	// It must be the real thing, and it must open the vault.
	plaintext := page[start : start+strings.IndexAny(page[start:], "\"< \n")]
	id, secret, err := auth.ParseServiceToken(plaintext)
	if err != nil {
		t.Fatalf("the displayed token is malformed: %v", err)
	}
	_, hash, err := h.manager.DB().ServiceToken(context.Background(), id)
	if err != nil {
		t.Fatalf("the token was not stored: %v", err)
	}
	if !auth.VerifyTokenSecret(secret, hash) {
		t.Fatal("the displayed token does not match what was stored")
	}

	// Reloading the page must not show it again.
	if again := body(t, h.get(t, "/coffres/"+vault.ID+"/appareils")); strings.Contains(again, plaintext) {
		t.Fatal("the token is shown again on a later visit")
	}
}

func TestCreatedTokenCarriesItsOptions(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	h.post(t, "/coffres/"+vault.ID+"/appareils", url.Values{
		"csrf": {h.csrf(t)}, "name": {"Sauvegarde"},
		"can_write": {"1"}, "expires": {"30"},
		"addresses": {"192.168.1.72, 10.0.0.0/8"},
	})

	tokens, err := h.manager.DB().ListServiceTokens(context.Background(), vault.ID)
	if err != nil {
		t.Fatalf("ListServiceTokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("%d tokens created, want 1", len(tokens))
	}

	tok := tokens[0]
	if !tok.CanWrite {
		t.Error("the write box was not applied")
	}
	if tok.ExpiresAt.IsZero() {
		t.Error("the expiry was not applied")
	}
	if len(tok.IPAllowlist) != 2 {
		t.Errorf("the allowlist is %v", tok.IPAllowlist)
	}
}

func TestMalformedAddressIsRefused(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	resp := h.post(t, "/coffres/"+vault.ID+"/appareils", url.Values{
		"csrf": {h.csrf(t)}, "name": {"HA"}, "addresses": {"pas-une-adresse"},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("a malformed address was accepted: %q", loc)
	}

	tokens, _ := h.manager.DB().ListServiceTokens(context.Background(), vault.ID)
	if len(tokens) != 0 {
		t.Fatal("a token was created despite the bad address")
	}
}

func TestRevokeFromTheBrowser(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	h.post(t, "/coffres/"+vault.ID+"/appareils", url.Values{
		"csrf": {h.csrf(t)}, "name": {"HA"},
	})
	tokens, _ := h.manager.DB().ListServiceTokens(ctx, vault.ID)

	resp := h.post(t, "/coffres/"+vault.ID+"/appareils/revoquer", url.Values{
		"csrf": {h.csrf(t)}, "token": {tokens[0].ID},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoking returned %d", resp.StatusCode)
	}

	// Revoked, not deleted: the audit log keeps pointing at something that
	// still has a name.
	tok, _, err := h.manager.DB().ServiceToken(ctx, tokens[0].ID)
	if err != nil {
		t.Fatalf("a revoked token vanished: %v", err)
	}
	if tok.Live(time.Now()) {
		t.Fatal("the token is still live after being revoked")
	}
}

// A manager must not be able to revoke a token belonging to another vault by
// posting its identifier.
func TestCannotRevokeAnotherVaultsToken(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	mine := h.newVault(t, "Maison")
	other := h.newVault(t, "Bureau")
	ctx := context.Background()

	h.post(t, "/coffres/"+other.ID+"/appareils", url.Values{
		"csrf": {h.csrf(t)}, "name": {"HA"},
	})
	tokens, _ := h.manager.DB().ListServiceTokens(ctx, other.ID)

	resp := h.post(t, "/coffres/"+mine.ID+"/appareils/revoquer", url.Values{
		"csrf": {h.csrf(t)}, "token": {tokens[0].ID},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("a token from another vault was revoked: %q", loc)
	}

	tok, _, _ := h.manager.DB().ServiceToken(ctx, tokens[0].ID)
	if !tok.RevokedAt.IsZero() {
		t.Fatal("the other vault's token was revoked")
	}
}

// The scope is set from the boxes ticked on the creation form.
func TestTokenIsCreatedWithItsScope(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	for _, name := range []string{"mqtt_password", "cle_wifi"} {
		loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: name}
		if _, err := h.manager.PutSecret(ctx, loc, []byte("v"), "", "cyril"); err != nil {
			t.Fatalf("PutSecret %s: %v", name, err)
		}
	}

	h.post(t, "/coffres/"+vault.ID+"/appareils", url.Values{
		"csrf": {h.csrf(t)}, "name": {"Home Assistant"},
		"secret": {"mqtt_password"},
	})

	tokens, _ := h.manager.DB().ListServiceTokens(ctx, vault.ID)
	if len(tokens) != 1 {
		t.Fatalf("%d tokens created, want 1", len(tokens))
	}
	if got := tokens[0].Secrets; len(got) != 1 || got[0] != "mqtt_password" {
		t.Fatalf("the scope is %v", got)
	}
	if tokens[0].AllowsSecret("cle_wifi") {
		t.Fatal("the token reaches a secret it was not scoped to")
	}
}

func TestScopeIsChangedFromTheBrowser(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	if _, err := h.manager.PutSecret(ctx, loc, []byte("v"), "", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	h.post(t, "/coffres/"+vault.ID+"/appareils", url.Values{
		"csrf": {h.csrf(t)}, "name": {"HA"},
	})
	tokens, _ := h.manager.DB().ListServiceTokens(ctx, vault.ID)
	id := tokens[0].ID

	// Narrow it.
	resp := h.post(t, "/coffres/"+vault.ID+"/appareils/portee", url.Values{
		"csrf": {h.csrf(t)}, "token": {id}, "secret": {"mqtt_password"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("saving the scope returned %d", resp.StatusCode)
	}
	tok, _, _ := h.manager.DB().ServiceToken(ctx, id)
	if len(tok.Secrets) != 1 {
		t.Fatalf("the scope is %v", tok.Secrets)
	}

	// Ticking nothing hands the whole vault back.
	h.post(t, "/coffres/"+vault.ID+"/appareils/portee", url.Values{
		"csrf": {h.csrf(t)}, "token": {id},
	})
	tok, _, _ = h.manager.DB().ServiceToken(ctx, id)
	if len(tok.Secrets) != 0 {
		t.Fatalf("the scope was not cleared: %v", tok.Secrets)
	}
}

// A posted name the vault does not hold is refused rather than stored, and a
// token from another vault is not this manager's to narrow.
func TestScopeRefusesWhatIsNotInTheVault(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	mine := h.newVault(t, "Maison")
	other := h.newVault(t, "Bureau")
	ctx := context.Background()

	h.post(t, "/coffres/"+mine.ID+"/appareils", url.Values{
		"csrf": {h.csrf(t)}, "name": {"HA"},
	})
	tokens, _ := h.manager.DB().ListServiceTokens(ctx, mine.ID)
	id := tokens[0].ID

	resp := h.post(t, "/coffres/"+mine.ID+"/appareils/portee", url.Values{
		"csrf": {h.csrf(t)}, "token": {id}, "secret": {"nexistepas"},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("an unknown secret was accepted: %q", loc)
	}

	resp = h.post(t, "/coffres/"+other.ID+"/appareils/portee", url.Values{
		"csrf": {h.csrf(t)}, "token": {id},
	})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Fatalf("a token from another vault was reached: %q", loc)
	}

	tok, _, _ := h.manager.DB().ServiceToken(ctx, id)
	if len(tok.Secrets) != 0 {
		t.Fatalf("a refused scope was stored: %v", tok.Secrets)
	}
}

// A token is shown exactly once. Making it easy to copy is the difference
// between a device that works and a token nobody can produce again.
func TestAFreshTokenCanBeCopied(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	resp := h.post(t, "/coffres/"+vault.ID+"/appareils", url.Values{
		"csrf": {h.csrf(t)}, "name": {"Home Assistant"},
	})
	page := body(t, resp)

	for _, want := range []string{`data-copy="#jeton"`, `data-copy="#essai"`, `data-copy="#ligne-ha"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the page showing a new token carries no %s", want)
		}
	}
	if !strings.Contains(page, "data-needs-js hidden") {
		t.Error("the copy controls are not hidden before the script runs")
	}
}

// The Host header is chosen by whoever sends the request, and the page that
// shows a fresh token puts it into a command the person is invited to paste.
// A header naming somewhere else would have the page hand the token over.

// postAs sends a form while claiming a given Host, the way a request arriving
// through a proxy that forwards one would.
func (h *harness) postAs(t *testing.T, host, path string, form url.Values) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = host

	// Attached by hand: the jar keys on the URL, and this request deliberately
	// claims to be somewhere else.
	u, err := url.Parse(h.srv.URL)
	if err != nil {
		t.Fatalf("parsing server URL: %v", err)
	}
	for _, c := range h.client.Jar.Cookies(u) {
		req.AddCookie(c)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestTheTokenCommandRefusesAnUnknownHost(t *testing.T) {
	h := newHarness(t, ServedNames([]string{"synsec.maison", "192.168.1.72"}))
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	resp := h.postAs(t, "mechant.example", "/coffres/"+vault.ID+"/appareils", url.Values{
		"csrf": {h.csrf(t)}, "name": {"Home Assistant"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("creating the token returned %d", resp.StatusCode)
	}
	page := body(t, resp)

	if strings.Contains(page, "mechant.example") {
		t.Fatal("the command shown carries the host the caller claimed")
	}
	if !strings.Contains(page, "synsec.maison") {
		t.Fatal("the command does not fall back to an address this server serves")
	}
}

// An address the certificate does cover must still be shown as it arrived, or
// every ordinary command would need editing by hand.
func TestTheTokenCommandKeepsAKnownHost(t *testing.T) {
	h := newHarness(t, ServedNames([]string{"synsec.maison"}))
	h.signIn(t)
	vault := h.newVault(t, "Maison")

	resp := h.postAs(t, "synsec.maison:8787", "/coffres/"+vault.ID+"/appareils", url.Values{
		"csrf": {h.csrf(t)}, "name": {"Home Assistant"},
	})
	if page := body(t, resp); !strings.Contains(page, "synsec.maison:8787") {
		t.Fatal("a known address was not kept, port included")
	}
}

func TestPublicHostFallsBackWithThePort(t *testing.T) {
	s := &Server{}
	ServedNames([]string{"synsec.maison", "192.168.1.72"})(s)

	cases := map[string]string{
		"synsec.maison:8787": "synsec.maison:8787",
		"192.168.1.72:8787":  "192.168.1.72:8787",
		"SYNSEC.MAISON:8787": "SYNSEC.MAISON:8787",
		"mechant.example":    "synsec.maison",
		"mechant.example:80": "synsec.maison:80",
	}
	for host, want := range cases {
		r := &http.Request{Host: host}
		if got := s.publicHost(r); got != want {
			t.Errorf("publicHost(%q) = %q, want %q", host, got, want)
		}
	}
}
