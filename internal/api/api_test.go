package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"synsec/internal/auth"
	"synsec/internal/store"
	"synsec/internal/vault"
)

type harness struct {
	srv     *httptest.Server
	manager *vault.Manager
	project store.Project
}

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

	p, err := m.CreateVault(ctx, "Maison", "domotique", "")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	srv := httptest.NewServer(New(m, opts...).Handler())
	t.Cleanup(srv.Close)

	return &harness{srv: srv, manager: m, project: p}
}

// mintToken creates a service token and returns the plaintext to present.
func (h *harness) mintToken(t *testing.T, mutate func(*store.ServiceToken)) string {
	t.Helper()

	id := store.MustNewID()
	tok := store.ServiceToken{
		ID:        id,
		Name:      "Home Assistant",
		ProjectID: h.project.ID,
		Env:       store.DefaultEnvironment,
	}
	if mutate != nil {
		mutate(&tok)
	}

	plaintext, hash, err := auth.NewServiceToken(id)
	if err != nil {
		t.Fatalf("auth.NewServiceToken: %v", err)
	}
	if err := h.manager.DB().CreateServiceToken(context.Background(), &tok, hash); err != nil {
		t.Fatalf("CreateServiceToken: %v", err)
	}
	return plaintext
}

func (h *harness) putSecret(t *testing.T, path, value string) {
	t.Helper()
	loc := store.SecretLocation{ProjectID: h.project.ID, Env: store.DefaultEnvironment, Name: path}
	if _, err := h.manager.PutSecret(context.Background(), loc, []byte(value), "", "test"); err != nil {
		t.Fatalf("PutSecret %s: %v", path, err)
	}
}

func (h *harness) do(t *testing.T, method, target, token string, body io.Reader) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, h.srv.URL+target, body)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func decodeJSON[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	return out
}

func bodyString(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	return string(b)
}

func TestHealthIsPublicAndQuiet(t *testing.T) {
	h := newHarness(t)

	resp := h.do(t, http.MethodGet, "/api/v1/health", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health returned %d", resp.StatusCode)
	}

	got := decodeJSON[map[string]string](t, resp)
	if got["status"] != "ready" {
		t.Fatalf("status is %q, want ready", got["status"])
	}
	// An unauthenticated endpoint must not disclose anything else.
	if len(got) != 1 {
		t.Fatalf("health disclosed %v", got)
	}
}

func TestSecretRoundTripOverHTTP(t *testing.T) {
	h := newHarness(t)
	token := h.mintToken(t, func(tok *store.ServiceToken) { tok.CanWrite = true })

	resp := h.do(t, http.MethodPut, "/api/v1/secrets/value?name=mqtt_password", token,
		strings.NewReader(`{"value":"s3cr3t"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d: %s", resp.StatusCode, bodyString(t, resp))
	}

	resp = h.do(t, http.MethodGet, "/api/v1/secrets/value?name=mqtt_password", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d: %s", resp.StatusCode, bodyString(t, resp))
	}
	got := decodeJSON[secretValue](t, resp)
	if got.Value != "s3cr3t" {
		t.Fatalf("value came back as %q", got.Value)
	}

	resp = h.do(t, http.MethodDelete, "/api/v1/secrets/value?name=mqtt_password", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE returned %d", resp.StatusCode)
	}
	resp = h.do(t, http.MethodGet, "/api/v1/secrets/value?name=mqtt_password", token, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET after DELETE returned %d, want 404", resp.StatusCode)
	}
}

// Every authentication failure must look identical from outside.
func TestAuthenticationFailures(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "mqtt_password", "s3cr3t")

	valid := h.mintToken(t, nil)
	revoked := h.mintToken(t, nil)
	revokedID, _, _ := auth.ParseServiceToken(revoked)
	if err := h.manager.DB().RevokeServiceToken(context.Background(), revokedID, time.Now()); err != nil {
		t.Fatalf("RevokeServiceToken: %v", err)
	}
	expired := h.mintToken(t, func(tok *store.ServiceToken) {
		tok.ExpiresAt = time.Now().Add(-time.Hour)
	})

	id, _, _ := auth.ParseServiceToken(valid)

	cases := map[string]string{
		"no token":      "",
		"not a token":   "bonjour",
		"wrong prefix":  "xyz_" + id + "_abc",
		"unknown id":    "syn_doesnotexist_abcdef",
		"wrong secret":  "syn_" + id + "_" + strings.Repeat("a", 52),
		"revoked token": revoked,
		"expired token": expired,
		"empty secret":  "syn_" + id + "_",
		"truncated":     "syn_" + id,
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			resp := h.do(t, http.MethodGet, "/api/v1/secrets/value?name=mqtt_password", token, nil)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s returned %d, want 401", name, resp.StatusCode)
			}
			body := decodeJSON[errorBody](t, resp)
			if body.Message != "invalid token" {
				t.Fatalf("%s produced the distinguishable message %q", name, body.Message)
			}
		})
	}
}

// A secret must never be reachable by putting the credential in the URL, where
// proxies and browser history would record it.
func TestTokenInQueryStringIsIgnored(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "mqtt_password", "s3cr3t")
	token := h.mintToken(t, nil)

	resp := h.do(t, http.MethodGet,
		"/api/v1/secrets/value?name=mqtt_password&token="+token, "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a token in the query string authenticated (%d)", resp.StatusCode)
	}
}

// A token opens one vault, and a token for another vault opens nothing here.
//
// This replaces the old separator-boundary test: with no hierarchy there is no
// prefix to escape from, and the vault is the whole of the scope.
func TestTokenReachesOnlyItsOwnVault(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "mqtt_password", "dedans")
	token := h.mintToken(t, nil)

	resp := h.do(t, http.MethodGet, "/api/v1/secrets/value?name=mqtt_password", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a secret in the token's own vault returned %d", resp.StatusCode)
	}

	// A vault the token was not issued for.
	other, err := h.manager.CreateVault(context.Background(), "Bureau", "", "")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	elsewhere := store.SecretLocation{
		ProjectID: other.ID, Env: store.DefaultEnvironment, Name: "mqtt_password",
	}
	if _, err := h.manager.PutSecret(context.Background(), elsewhere, []byte("dehors"), "", "test"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	// The listing shows the token's vault and nothing else - same name, other
	// vault, and it must not appear.
	resp = h.do(t, http.MethodGet, "/api/v1/secrets", token, nil)
	listed := decodeJSON[struct {
		Secrets []secretSummary `json:"secrets"`
	}](t, resp)
	if len(listed.Secrets) != 1 {
		t.Fatalf("listing returned %d secrets, want the vault's 1", len(listed.Secrets))
	}

	got := decodeJSON[secretValue](t,
		h.do(t, http.MethodGet, "/api/v1/secrets/value?name=mqtt_password", token, nil))
	if got.Value != "dedans" {
		t.Fatalf("the token read %q, which belongs to another vault", got.Value)
	}
}

func TestReadOnlyTokenCannotWrite(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "mqtt_password", "s3cr3t")
	token := h.mintToken(t, nil) // CanWrite is false by default

	resp := h.do(t, http.MethodPut, "/api/v1/secrets/value?name=mqtt_password", token,
		strings.NewReader(`{"value":"nouveau"}`))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a read-only token wrote a secret (%d)", resp.StatusCode)
	}

	resp = h.do(t, http.MethodDelete, "/api/v1/secrets/value?name=mqtt_password", token, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a read-only token deleted a secret (%d)", resp.StatusCode)
	}
}

func TestMalformedNamesAreRejected(t *testing.T) {
	h := newHarness(t)
	token := h.mintToken(t, nil)

	for label, name := range map[string]string{
		"empty":     "",
		"blank":     "%20",
		"very long": strings.Repeat("a", store.MaxSecretNameLength+1),
	} {
		t.Run(label, func(t *testing.T) {
			resp := h.do(t, http.MethodGet, "/api/v1/secrets/value?name="+name, token, nil)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("the name %q returned %d, want 400", name, resp.StatusCode)
			}
		})
	}

	// A well-formed name that simply does not exist is a 404, not a 400: the
	// distinction is what tells a device "you asked wrongly" from "it is gone".
	resp := h.do(t, http.MethodGet, "/api/v1/secrets/value?name=nexistepas", token, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an unknown name returned %d, want 404", resp.StatusCode)
	}
}

func TestIPAllowlistIsEnforced(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "mqtt_password", "s3cr3t")

	allowed := h.mintToken(t, func(tok *store.ServiceToken) {
		tok.IPAllowlist = []string{"127.0.0.0/8", "::1"}
	})
	refused := h.mintToken(t, func(tok *store.ServiceToken) {
		tok.IPAllowlist = []string{"10.0.0.1"}
	})

	resp := h.do(t, http.MethodGet, "/api/v1/secrets/value?name=mqtt_password", allowed, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("an allowed address returned %d", resp.StatusCode)
	}
	resp = h.do(t, http.MethodGet, "/api/v1/secrets/value?name=mqtt_password", refused, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a refused address returned %d, want 401", resp.StatusCode)
	}
}

// Believing X-Forwarded-For without a proxy in front would let any caller
// grant itself any address, and the allowlist with it.
func TestForwardedHeaderIgnoredByDefault(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "mqtt_password", "s3cr3t")
	token := h.mintToken(t, func(tok *store.ServiceToken) {
		tok.IPAllowlist = []string{"10.0.0.1"}
	})

	req, _ := http.NewRequest(http.MethodGet,
		h.srv.URL+"/api/v1/secrets/value?name=mqtt_password", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a forged X-Forwarded-For was believed (%d)", resp.StatusCode)
	}
}

// pin restricts a secret to one address.
func (h *harness) pin(t *testing.T, path, network string) {
	t.Helper()
	ctx := context.Background()

	loc := store.SecretLocation{ProjectID: h.project.ID, Env: store.DefaultEnvironment, Name: path}
	secret, err := h.manager.DB().SecretMeta(ctx, loc)
	if err != nil {
		t.Fatalf("SecretMeta: %v", err)
	}
	if err := h.manager.DB().AddSecretNetwork(ctx, secret.ID, network, "test"); err != nil {
		t.Fatalf("AddSecretNetwork: %v", err)
	}
}

// The restriction belongs to the secret, so a valid token in scope is still
// refused from an address the secret was not pinned to.
func TestPinnedSecretIsRefusedFromElsewhere(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "zigbee_cle", "s3cr3t")
	token := h.mintToken(t, nil)

	// The test client comes from loopback, which is not in this list.
	h.pin(t, "zigbee_cle", "10.0.0.1")

	resp := h.do(t, http.MethodGet, "/api/v1/secrets/value?name=zigbee_cle", token, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a pinned secret returned %d from another address, want 403", resp.StatusCode)
	}
	if body := bodyString(t, resp); strings.Contains(body, "s3cr3t") {
		t.Fatal("the value was returned despite the restriction")
	}
}

func TestPinnedSecretIsServedFromItsAddress(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "zigbee_cle", "s3cr3t")
	token := h.mintToken(t, nil)

	h.pin(t, "zigbee_cle", "127.0.0.0/8")

	resp := h.do(t, http.MethodGet, "/api/v1/secrets/value?name=zigbee_cle", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a pinned secret returned %d from its own address", resp.StatusCode)
	}
	if got := decodeJSON[secretValue](t, resp).Value; got != "s3cr3t" {
		t.Fatalf("the value came back as %q", got)
	}
}

func TestSealedServerServesNothing(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "mqtt_password", "s3cr3t")
	token := h.mintToken(t, nil)
	h.manager.Seal()

	resp := h.do(t, http.MethodGet, "/api/v1/secrets/value?name=mqtt_password", token, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a sealed server returned %d, want 503", resp.StatusCode)
	}

	// Health must still answer, and must say so.
	resp = h.do(t, http.MethodGet, "/api/v1/health", "", nil)
	if got := decodeJSON[map[string]string](t, resp)["status"]; got != "sealed" {
		t.Fatalf("health reports %q on a sealed server", got)
	}
}

func TestResponsesAreNotCacheable(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "mqtt_password", "s3cr3t")
	token := h.mintToken(t, nil)

	resp := h.do(t, http.MethodGet, "/api/v1/secrets/value?name=mqtt_password", token, nil)
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control is %q, want no-store", got)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options is %q", got)
	}
}

func TestReadsAndWritesAreAudited(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := h.mintToken(t, func(tok *store.ServiceToken) { tok.CanWrite = true })

	h.do(t, http.MethodPut, "/api/v1/secrets/value?name=mqtt_password", token,
		strings.NewReader(`{"value":"s3cr3t"}`))
	h.do(t, http.MethodGet, "/api/v1/secrets/value?name=mqtt_password", token, nil)

	entries, err := h.manager.DB().ListAudit(ctx, store.AuditFilter{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}

	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		seen[e.Action] = true
		if strings.Contains(e.Detail, "s3cr3t") || strings.Contains(e.Target, "s3cr3t") {
			t.Fatal("the audit log recorded a secret value")
		}
	}
	for _, action := range []string{"secret.read", "secret.write"} {
		if !seen[action] {
			t.Fatalf("%s was not recorded; log holds %v", action, seen)
		}
	}
}

func TestDeniedAccessIsAudited(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "zigbee_key", "s3cr3t")

	// A read-only token attempting a write is now the refusal worth recording:
	// with the vault as the whole scope, intent is what a token can overstep.
	token := h.mintToken(t, nil)
	h.do(t, http.MethodPut, "/api/v1/secrets/value?name=zigbee_key", token,
		strings.NewReader(`{"value":"nouveau"}`))

	entries, err := h.manager.DB().ListAudit(context.Background(),
		store.AuditFilter{Action: "access.denied"})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d denials recorded, want 1", len(entries))
	}
	if entries[0].Target != "zigbee_key" {
		t.Fatalf("the denial names %q", entries[0].Target)
	}
}

// A token narrowed to a few entries reaches those and nothing else, even
// though it was issued for the vault they live in.
func TestScopedTokenReachesOnlyItsSecrets(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "mqtt_password", "s3cr3t")
	h.putSecret(t, "cle_wifi", "hunter2")

	token := h.mintToken(t, func(tok *store.ServiceToken) {
		tok.CanWrite = true
		tok.Secrets = []string{"mqtt_password"}
	})

	resp := h.do(t, http.MethodGet, "/api/v1/secrets/value?name=mqtt_password", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the token cannot read the secret it was scoped to (%d)", resp.StatusCode)
	}

	for _, target := range []string{
		"/api/v1/secrets/value?name=cle_wifi",
		"/api/v1/secrets/value?name=nexistepas",
	} {
		if resp := h.do(t, http.MethodGet, target, token, nil); resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s returned %d, want 403", target, resp.StatusCode)
		}
	}

	// Writing and deleting are held to the same scope.
	body := strings.NewReader(`{"value":"x"}`)
	if resp := h.do(t, http.MethodPut, "/api/v1/secrets/value?name=cle_wifi", token, body); resp.StatusCode != http.StatusForbidden {
		t.Errorf("PUT outside the scope returned %d, want 403", resp.StatusCode)
	}
	if resp := h.do(t, http.MethodDelete, "/api/v1/secrets/value?name=cle_wifi", token, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("DELETE outside the scope returned %d, want 403", resp.StatusCode)
	}
}

// The listing is the one place a narrowed token could learn what else the
// vault holds.
func TestScopedTokenListsOnlyItsSecrets(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "mqtt_password", "s3cr3t")
	h.putSecret(t, "cle_wifi", "hunter2")

	token := h.mintToken(t, func(tok *store.ServiceToken) {
		tok.Secrets = []string{"mqtt_password"}
	})

	page := bodyString(t, h.do(t, http.MethodGet, "/api/v1/secrets", token, nil))
	if !strings.Contains(page, "mqtt_password") {
		t.Fatal("the listing hides the secret the token was scoped to")
	}
	if strings.Contains(page, "cle_wifi") {
		t.Fatal("the listing names a secret outside the token's scope")
	}
}

// A token without a stated scope keeps opening the whole vault, which is what
// every token issued before scopes existed does.
func TestTokenWithoutScopeReachesTheWholeVault(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "mqtt_password", "s3cr3t")
	h.putSecret(t, "cle_wifi", "hunter2")

	token := h.mintToken(t, nil)
	for _, name := range []string{"mqtt_password", "cle_wifi"} {
		resp := h.do(t, http.MethodGet, "/api/v1/secrets/value?name="+name, token, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("an unscoped token cannot read %s (%d)", name, resp.StatusCode)
		}
	}
}

// A read reports the version it served. It used to answer 0 whatever the
// secret's history, which made the field worse than absent.
func TestReadReportsTheVersion(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "home_assistant", "v1")
	h.putSecret(t, "home_assistant", "v2")
	token := h.mintToken(t, nil)

	resp := h.do(t, http.MethodGet, "/api/v1/secrets/value?name=home_assistant", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reading returned %d", resp.StatusCode)
	}

	body := decodeJSON[struct {
		Value   string `json:"value"`
		Version int64  `json:"version"`
	}](t, resp)

	if body.Value != "v2" {
		t.Fatalf("the value is %q, want the latest", body.Value)
	}
	if body.Version != 2 {
		t.Fatalf("the version is %d, want 2", body.Version)
	}
}

// The address restriction governs writing and deleting as well as reading.
//
// Governing reads alone would let the very device it was written against
// overwrite or destroy the secret from anywhere - the opposite of what pinning
// a secret to an address is for, and deletion is the most damaging of the
// three.
func TestPinnedSecretIsWriteProtectedToo(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "mqtt_password", "s3cr3t")
	h.pin(t, "mqtt_password", "203.0.113.9") // an address the test never calls from

	token := h.mintToken(t, func(tok *store.ServiceToken) { tok.CanWrite = true })

	body := strings.NewReader(`{"value":"remplace"}`)
	if resp := h.do(t, http.MethodPut, "/api/v1/secrets/value?name=mqtt_password", token, body); resp.StatusCode != http.StatusForbidden {
		t.Errorf("PUT from a disallowed address returned %d, want 403", resp.StatusCode)
	}
	if resp := h.do(t, http.MethodDelete, "/api/v1/secrets/value?name=mqtt_password", token, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("DELETE from a disallowed address returned %d, want 403", resp.StatusCode)
	}

	// And the secret is intact: neither refusal was a refusal after the fact.
	resp := h.do(t, http.MethodGet, "/api/v1/secrets", token, nil)
	if !strings.Contains(bodyString(t, resp), "mqtt_password") {
		t.Fatal("the secret was deleted despite the refusal")
	}
}

// Creating an entry is not something an address list written for another entry
// can govern, so a name that does not exist yet is not blocked.
func TestPinningDoesNotBlockCreatingANewName(t *testing.T) {
	h := newHarness(t)
	h.putSecret(t, "mqtt_password", "s3cr3t")
	h.pin(t, "mqtt_password", "203.0.113.9")

	token := h.mintToken(t, func(tok *store.ServiceToken) { tok.CanWrite = true })

	body := strings.NewReader(`{"value":"nouveau"}`)
	resp := h.do(t, http.MethodPut, "/api/v1/secrets/value?name=cle_wifi", token, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("creating a new secret returned %d", resp.StatusCode)
	}
}

// A browser or a device that reached the real server must be told never to try
// plain HTTP again.
func TestStrictTransportSecurityIsSet(t *testing.T) {
	h := newHarness(t)
	token := h.mintToken(t, nil)

	resp := h.do(t, http.MethodGet, "/api/v1/secrets", token, nil)
	if got := resp.Header.Get("Strict-Transport-Security"); got == "" {
		t.Fatal("no Strict-Transport-Security header on an API response")
	}

	// Including on the unauthenticated endpoint, which is the first thing many
	// clients touch.
	resp = h.do(t, http.MethodGet, "/api/v1/health", "", nil)
	if got := resp.Header.Get("Strict-Transport-Security"); got == "" {
		t.Fatal("no Strict-Transport-Security header on the health endpoint")
	}
}
