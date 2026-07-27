package vault

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"synsec/internal/store"
)

// newManager builds an initialised manager over a throwaway database.
//
// It deliberately uses the real unseal provider for the platform - DPAPI on
// Windows, TPM or key file on Linux - because that path is the one that runs
// unattended at every boot and is worth exercising for real.
func newManager(t *testing.T) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()

	db, err := store.Open(filepath.Join(dir, "synsec.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	m := New(db, dir)
	res, err := m.Initialize(context.Background())
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	t.Cleanup(m.Seal)
	return m, res.RecoveryCode
}

func newVault(t *testing.T, m *Manager) store.Project {
	t.Helper()
	p, err := m.CreateVault(context.Background(), "Maison", "domotique", "")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	return p
}

func loc(p store.Project, path string) store.SecretLocation {
	return store.SecretLocation{ProjectID: p.ID, Env: store.DefaultEnvironment, Name: path}
}

func TestInitializeCreatesTwoWaysIn(t *testing.T) {
	m, code := newManager(t)
	ctx := context.Background()

	if m.Sealed() {
		t.Fatal("manager is sealed straight after Initialize")
	}
	if !validRecoveryCode(code) {
		t.Fatalf("recovery code %q has the wrong shape", code)
	}

	// One slot for the host, one for the printed code. Fewer than two means a
	// single mishap destroys everything.
	n, err := m.DB().CountKeySlots(ctx)
	if err != nil {
		t.Fatalf("CountKeySlots: %v", err)
	}
	if n != 2 {
		t.Fatalf("setup left %d key slots, want 2", n)
	}
}

func TestInitializeRefusesToRunTwice(t *testing.T) {
	m, _ := newManager(t)
	if _, err := m.Initialize(context.Background()); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second Initialize returned %v, want ErrAlreadyInitialized", err)
	}
}

func TestSecretRoundTrip(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	p := newVault(t, m)

	want := []byte("mon-mot-de-passe-mqtt")
	if _, err := m.PutSecret(ctx, loc(p, "mqtt_password"), want, "", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	got, err := m.GetSecret(ctx, loc(p, "mqtt_password"))
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// The whole point of the machine slot: a reboot must restore service with
// nobody present to type anything.
func TestUnsealFromHostKeystore(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	p := newVault(t, m)

	want := []byte("valeur")
	if _, err := m.PutSecret(ctx, loc(p, "mqtt_password"), want, "", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	m.Seal()
	if !m.Sealed() {
		t.Fatal("Seal did not seal the manager")
	}
	if _, err := m.GetSecret(ctx, loc(p, "mqtt_password")); !errors.Is(err, ErrSealed) {
		t.Fatalf("reading while sealed returned %v, want ErrSealed", err)
	}

	if err := m.Unseal(ctx); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	got, err := m.GetSecret(ctx, loc(p, "mqtt_password"))
	if err != nil {
		t.Fatalf("GetSecret after unsealing: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("value changed across a seal cycle: got %q, want %q", got, want)
	}
}

func TestUnsealWithRecoveryCode(t *testing.T) {
	m, code := newManager(t)
	ctx := context.Background()
	p := newVault(t, m)
	m.PutSecret(ctx, loc(p, "x"), []byte("valeur"), "", "cyril")

	m.Seal()
	if err := m.UnsealWithRecovery(ctx, code); err != nil {
		t.Fatalf("UnsealWithRecovery: %v", err)
	}

	got, err := m.GetSecret(ctx, loc(p, "x"))
	if err != nil {
		t.Fatalf("GetSecret after recovery: %v", err)
	}
	if !bytes.Equal(got, []byte("valeur")) {
		t.Fatalf("got %q after recovery", got)
	}
}

// Someone reading a code off a printed card should not be defeated by case,
// by the dashes, or by the difference between the letter O and a zero.
func TestRecoveryCodeToleratesTranscription(t *testing.T) {
	m, code := newManager(t)
	ctx := context.Background()

	mangled := map[string]string{
		"lower case":  strings.ToLower(code),
		"no dashes":   strings.ReplaceAll(code, "-", ""),
		"spaces":      strings.ReplaceAll(code, "-", " "),
		"letter O":    strings.ReplaceAll(code, "0", "O"),
		"letter l":    strings.ReplaceAll(strings.ToLower(code), "1", "l"),
		"with spaces": " " + code + "\n",
	}
	for name, variant := range mangled {
		t.Run(name, func(t *testing.T) {
			m.Seal()
			if err := m.UnsealWithRecovery(ctx, variant); err != nil {
				t.Fatalf("code written as %s was rejected: %v", name, err)
			}
		})
	}
}

// CheckRecoveryCode proves possession of the printed kit without leaving the
// server open: a command that only needs the proof must not have the side
// effect of unsealing.
func TestCheckRecoveryCodeLeavesTheVaultSealed(t *testing.T) {
	m, code := newManager(t)
	ctx := context.Background()
	m.Seal()

	if err := m.CheckRecoveryCode(ctx, code); err != nil {
		t.Fatalf("the right code was rejected: %v", err)
	}
	if !m.Sealed() {
		t.Fatal("checking the code left the vault unsealed")
	}

	for name, bad := range map[string]string{
		"empty":     "",
		"too short": "ABCD-EFGH",
		"wrong":     "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ",
	} {
		t.Run(name, func(t *testing.T) {
			if err := m.CheckRecoveryCode(ctx, bad); !errors.Is(err, ErrBadRecoveryCode) {
				t.Fatalf("code %q returned %v, want ErrBadRecoveryCode", bad, err)
			}
		})
	}

	// And it works just as well while the server is running.
	if err := m.Unseal(ctx); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if err := m.CheckRecoveryCode(ctx, code); err != nil {
		t.Fatalf("the code was rejected on an open vault: %v", err)
	}
}

func TestBadRecoveryCodeIsRejected(t *testing.T) {
	m, code := newManager(t)
	ctx := context.Background()
	m.Seal()

	for name, bad := range map[string]string{
		"empty":     "",
		"too short": "ABCD-EFGH",
		"wrong":     "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ",
		"truncated": code[:len(code)-2],
	} {
		t.Run(name, func(t *testing.T) {
			if err := m.UnsealWithRecovery(ctx, bad); !errors.Is(err, ErrBadRecoveryCode) {
				t.Fatalf("code %q returned %v, want ErrBadRecoveryCode", bad, err)
			}
			if !m.Sealed() {
				t.Fatal("a rejected recovery code left the manager unsealed")
			}
		})
	}
}

// Recovering onto a fresh machine has to re-seal the root key to the new host,
// or the printed code would be needed at every single boot from then on.
func TestReprovisionAfterRecovery(t *testing.T) {
	m, code := newManager(t)
	ctx := context.Background()
	p := newVault(t, m)
	m.PutSecret(ctx, loc(p, "x"), []byte("valeur"), "", "cyril")

	m.Seal()
	if err := m.UnsealWithRecovery(ctx, code); err != nil {
		t.Fatalf("UnsealWithRecovery: %v", err)
	}
	if _, err := m.ReprovisionMachineSlot(ctx); err != nil {
		t.Fatalf("ReprovisionMachineSlot: %v", err)
	}

	m.Seal()
	if err := m.Unseal(ctx); err != nil {
		t.Fatalf("Unseal after reprovisioning: %v", err)
	}
	if _, err := m.GetSecret(ctx, loc(p, "x")); err != nil {
		t.Fatalf("GetSecret after reprovisioning: %v", err)
	}
}

// Secrets are read one at a time. Nothing hands back a set, so the property
// worth holding is that each entry comes back exactly as it went in.
func TestSecretsAreIndependentEntries(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	p := newVault(t, m)

	want := map[string]string{
		"mqtt_user":     "homeassistant",
		"mqtt_password": "s3cr3t",
		"zigbee_key":    "0xdeadbeef",
	}
	for name, value := range want {
		if _, err := m.PutSecret(ctx, loc(p, name), []byte(value), "", "cyril"); err != nil {
			t.Fatalf("PutSecret %s: %v", name, err)
		}
	}

	for name, value := range want {
		got, err := m.GetSecret(ctx, loc(p, name))
		if err != nil {
			t.Fatalf("GetSecret %s: %v", name, err)
		}
		if string(got) != value {
			t.Fatalf("%s came back as %q, want %q", name, got, value)
		}
	}

	// The vault lists them all, and the listing carries no value.
	listed, err := m.DB().ListSecrets(ctx, p.ID, store.DefaultEnvironment)
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(listed) != len(want) {
		t.Fatalf("the vault lists %d secrets, want %d", len(listed), len(want))
	}
}

func TestRevertRestoresAnEarlierValue(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	p := newVault(t, m)
	l := loc(p, "mqtt_password")

	m.PutSecret(ctx, l, []byte("premier"), "", "cyril")
	m.PutSecret(ctx, l, []byte("deuxieme"), "", "cyril")

	reverted, err := m.RevertSecret(ctx, l, 1, "cyril")
	if err != nil {
		t.Fatalf("RevertSecret: %v", err)
	}
	// Reverting writes a new version rather than moving a pointer backwards.
	if reverted.CurrentVersion != 3 {
		t.Fatalf("revert produced version %d, want 3", reverted.CurrentVersion)
	}

	got, err := m.GetSecret(ctx, l)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(got) != "premier" {
		t.Fatalf("after reverting, value is %q, want premier", got)
	}

	if _, err := m.RevertSecret(ctx, l, 99, "cyril"); err == nil {
		t.Fatal("reverting to a version that does not exist was accepted")
	}
}

func TestRotateVaultKeyKeepsEverythingReadable(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	p := newVault(t, m)
	l := loc(p, "mqtt_password")

	m.PutSecret(ctx, l, []byte("v1"), "", "cyril")
	m.PutSecret(ctx, l, []byte("v2"), "", "cyril")
	m.PutSecret(ctx, loc(p, "autre"), []byte("autre"), "", "cyril")

	before, err := m.DB().Project(ctx, p.ID)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}

	if err := m.RotateVaultKey(ctx, p.ID); err != nil {
		t.Fatalf("RotateVaultKey: %v", err)
	}

	after, err := m.DB().Project(ctx, p.ID)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if bytes.Equal(before.WrappedDEK, after.WrappedDEK) {
		t.Fatal("rotation left the wrapped vault key unchanged")
	}

	got, err := m.GetSecret(ctx, l)
	if err != nil {
		t.Fatalf("GetSecret after rotation: %v", err)
	}
	if string(got) != "v2" {
		t.Fatalf("current value is %q after rotation, want v2", got)
	}

	// History must rotate too: versions still readable under the old key would
	// mean the rotation achieved nothing.
	if _, err := m.RevertSecret(ctx, l, 1, "cyril"); err != nil {
		t.Fatalf("older version unreadable after rotation: %v", err)
	}
	older, err := m.GetSecret(ctx, l)
	if err != nil {
		t.Fatalf("GetSecret after reverting: %v", err)
	}
	if string(older) != "v1" {
		t.Fatalf("reverted value is %q, want v1", older)
	}
}

func TestSealedManagerRefusesEverything(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	p := newVault(t, m)
	m.Seal()

	if _, err := m.CreateVault(ctx, "Autre", "", ""); !errors.Is(err, ErrSealed) {
		t.Fatalf("CreateVault while sealed returned %v", err)
	}
	if _, err := m.PutSecret(ctx, loc(p, "x"), []byte("v"), "", "cyril"); !errors.Is(err, ErrSealed) {
		t.Fatalf("PutSecret while sealed returned %v", err)
	}
	if _, err := m.GetSecret(ctx, loc(p, "x")); !errors.Is(err, ErrSealed) {
		t.Fatalf("GetSecret while sealed returned %v", err)
	}
	if err := m.RotateVaultKey(ctx, p.ID); !errors.Is(err, ErrSealed) {
		t.Fatalf("RotateVaultKey while sealed returned %v", err)
	}
}

// A vault's key is authenticated against its identifier, so a ciphertext moved
// between vaults must not decrypt.
func TestVaultsAreIsolated(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()

	a, err := m.CreateVault(ctx, "Maison", "", "")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	b, err := m.CreateVault(ctx, "Bureau", "", "")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	if _, err := m.PutSecret(ctx, loc(a, "x"), []byte("secret de la maison"), "", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	if _, err := m.GetSecret(ctx, loc(b, "x")); err == nil {
		t.Fatal("a secret was readable from the wrong vault")
	}
}

func TestRecoveryCodeShape(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		code, err := NewRecoveryCode()
		if err != nil {
			t.Fatalf("NewRecoveryCode: %v", err)
		}
		if seen[code] {
			t.Fatalf("NewRecoveryCode repeated %q", code)
		}
		seen[code] = true

		groups := strings.Split(code, "-")
		if len(groups) != recoveryGroups {
			t.Fatalf("code %q has %d groups, want %d", code, len(groups), recoveryGroups)
		}
		for _, g := range groups {
			if len(g) != recoveryGroup {
				t.Fatalf("code %q has a group of %d characters, want %d", code, len(g), recoveryGroup)
			}
		}
		// Crockford's alphabet exists to keep these out.
		if strings.ContainsAny(code, "ILOU") {
			t.Fatalf("code %q contains an ambiguous character", code)
		}
	}
}
