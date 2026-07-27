package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"synsec/internal/store"
)

// The address restriction pins a secret to the machine that consumes it. It is
// checked when a service token is used, and must not reach the browser: the
// interface is opened from a phone, a laptop, wherever its owner happens to be,
// and locking them out of their own secret from the sofa is not the point.
func TestAddressRestrictionDoesNotReachTheBrowser(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	vault := h.newVault(t, "Maison")
	ctx := context.Background()

	loc := store.SecretLocation{ProjectID: vault.ID, Env: store.DefaultEnvironment, Name: "mqtt_password"}
	if _, err := h.manager.PutSecret(ctx, loc, []byte("s3cr3t"), "", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	secret, err := h.manager.DB().SecretMeta(ctx, loc)
	if err != nil {
		t.Fatalf("SecretMeta: %v", err)
	}

	// An address the test server certainly does not call from.
	if err := h.manager.DB().AddSecretNetwork(ctx, secret.ID, "203.0.113.9", "cyril"); err != nil {
		t.Fatalf("AddSecretNetwork: %v", err)
	}

	resp := h.get(t, "/coffres/"+vault.ID+"/secret?name=mqtt_password")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the secret page returned %d from a non-listed address", resp.StatusCode)
	}
	if page := body(t, resp); !strings.Contains(page, "s3cr3t") {
		t.Fatal("the value is withheld from its owner in the browser")
	}
}
