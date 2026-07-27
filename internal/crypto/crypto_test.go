package crypto

import (
	"bytes"
	"errors"
	"testing"
)

// testArgon2 keeps the unit tests fast; production uses DefaultArgon2.
var testArgon2 = Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}

func mustKey(t *testing.T) *Key {
	t.Helper()
	k, err := NewRandomKey()
	if err != nil {
		t.Fatalf("NewRandomKey: %v", err)
	}
	t.Cleanup(k.Zero)
	return k
}

func ref() SecretRef {
	return SecretRef{ProjectID: "maison", Env: "prod", Name: "mqtt_password", Version: 1}
}

func TestSecretRoundTrip(t *testing.T) {
	dek := mustKey(t)
	want := []byte("hunter2")

	blob, err := SealSecret(dek, ref(), want)
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}
	if bytes.Contains(blob, want) {
		t.Fatal("plaintext appears verbatim in the ciphertext")
	}

	got, err := OpenSecret(dek, ref(), blob)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round trip gave %q, want %q", got, want)
	}
}

// A ciphertext must be pinned to its exact location. This is the property that
// stops someone with write access to the database from promoting a test
// credential into production, or rolling a secret back to an older value.
func TestSecretIsBoundToItsLocation(t *testing.T) {
	dek := mustKey(t)
	blob, err := SealSecret(dek, ref(), []byte("hunter2"))
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}

	moved := map[string]SecretRef{
		"other project":     {ProjectID: "voisin", Env: "prod", Name: "mqtt_password", Version: 1},
		"other environment": {ProjectID: "maison", Env: "dev", Name: "mqtt_password", Version: 1},
		"other path":        {ProjectID: "maison", Env: "prod", Name: "mqtt_user", Version: 1},
		"other version":     {ProjectID: "maison", Env: "prod", Name: "mqtt_password", Version: 2},
	}
	for name, r := range moved {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenSecret(dek, r, blob); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("moving the ciphertext to a %s succeeded (err = %v)", name, err)
			}
		})
	}
}

// Naive concatenation of the AAD fields would make these two references
// produce identical authenticated data, so a ciphertext could be moved between
// them undetected. Length-prefixing is what prevents it.
func TestAADIsUnambiguous(t *testing.T) {
	dek := mustKey(t)
	a := SecretRef{ProjectID: "maison", Env: "pro", Name: "d/mqtt", Version: 1}
	b := SecretRef{ProjectID: "maison", Env: "prod", Name: "/mqtt", Version: 1}

	blob, err := SealSecret(dek, a, []byte("hunter2"))
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}
	if _, err := OpenSecret(dek, b, blob); !errors.Is(err, ErrDecrypt) {
		t.Fatal("two references with the same concatenation opened the same blob")
	}
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	dek := mustKey(t)
	blob, err := SealSecret(dek, ref(), []byte("hunter2"))
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}

	for i := range blob {
		tampered := bytes.Clone(blob)
		tampered[i] ^= 0x01
		if _, err := OpenSecret(dek, ref(), tampered); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("flipping a bit at offset %d went undetected", i)
		}
	}
}

func TestWrongKeyIsRejected(t *testing.T) {
	blob, err := SealSecret(mustKey(t), ref(), []byte("hunter2"))
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}
	if _, err := OpenSecret(mustKey(t), ref(), blob); !errors.Is(err, ErrDecrypt) {
		t.Fatal("a different key opened the blob")
	}
}

func TestNonceIsFresh(t *testing.T) {
	dek := mustKey(t)
	seen := make(map[string]bool, 256)
	for i := 0; i < 256; i++ {
		blob, err := SealSecret(dek, ref(), []byte("same plaintext"))
		if err != nil {
			t.Fatalf("SealSecret: %v", err)
		}
		nonce := string(blob[1 : 1+nonceSize])
		if seen[nonce] {
			t.Fatal("nonce reused across two seals of the same value")
		}
		seen[nonce] = true
	}
}

func TestDEKWrapRoundTrip(t *testing.T) {
	root, dek := mustKey(t), mustKey(t)

	blob, err := WrapDEK(root, "maison", dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	got, err := UnwrapDEK(root, "maison", blob)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	defer got.Zero()
	if !bytes.Equal(got.Bytes(), dek.Bytes()) {
		t.Fatal("unwrapped project key differs from the original")
	}

	if _, err := UnwrapDEK(root, "voisin", blob); !errors.Is(err, ErrDecrypt) {
		t.Fatal("a project key unwrapped under the wrong project")
	}
}

func TestSecretSlotRoundTrip(t *testing.T) {
	root := mustKey(t)
	slot, err := NewSecretSlot("primary", SlotPassphrase, root, []byte("correct horse"), testArgon2)
	if err != nil {
		t.Fatalf("NewSecretSlot: %v", err)
	}

	got, err := slot.Unseal([]byte("correct horse"))
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	defer got.Zero()
	if !bytes.Equal(got.Bytes(), root.Bytes()) {
		t.Fatal("unsealed root key differs from the original")
	}

	if _, err := slot.Unseal([]byte("wrong horse")); !errors.Is(err, ErrSlotMismatch) {
		t.Fatalf("wrong passphrase unsealed the slot (err = %v)", err)
	}
}

// Every slot wraps the same root key, so losing the passphrase must not mean
// losing the secrets: the recovery code and the machine keystore each open the
// server on their own.
func TestAnySlotUnsealsTheSameRoot(t *testing.T) {
	root := mustKey(t)
	hostKey := mustKey(t)

	pass, err := NewSecretSlot("primary", SlotPassphrase, root, []byte("correct horse"), testArgon2)
	if err != nil {
		t.Fatalf("passphrase slot: %v", err)
	}
	recov, err := NewSecretSlot("recovery", SlotRecovery, root, []byte("AAAA-BBBB-CCCC"), testArgon2)
	if err != nil {
		t.Fatalf("recovery slot: %v", err)
	}
	machine, err := NewMachineSlot("host", root, hostKey)
	if err != nil {
		t.Fatalf("machine slot: %v", err)
	}

	fromPass, err := pass.Unseal([]byte("correct horse"))
	if err != nil {
		t.Fatalf("unseal by passphrase: %v", err)
	}
	defer fromPass.Zero()
	fromRecov, err := recov.Unseal([]byte("AAAA-BBBB-CCCC"))
	if err != nil {
		t.Fatalf("unseal by recovery code: %v", err)
	}
	defer fromRecov.Zero()
	fromMachine, err := machine.UnsealWith(hostKey)
	if err != nil {
		t.Fatalf("unseal by host keystore: %v", err)
	}
	defer fromMachine.Zero()

	for name, k := range map[string]*Key{
		"passphrase": fromPass,
		"recovery":   fromRecov,
		"machine":    fromMachine,
	} {
		if !bytes.Equal(k.Bytes(), root.Bytes()) {
			t.Fatalf("%s slot yielded a different root key", name)
		}
	}
}

// A slot blob must not be transplantable into another slot entry.
func TestSlotBlobIsBoundToItsIdentity(t *testing.T) {
	root, hostKey := mustKey(t), mustKey(t)
	machine, err := NewMachineSlot("host", root, hostKey)
	if err != nil {
		t.Fatalf("NewMachineSlot: %v", err)
	}

	forged := &KeySlot{ID: "other-host", Kind: SlotMachine, Blob: machine.Blob}
	if _, err := forged.UnsealWith(hostKey); !errors.Is(err, ErrSlotMismatch) {
		t.Fatal("a slot blob opened under a different slot identity")
	}
}

func TestZeroedKeyIsUnusable(t *testing.T) {
	k, err := NewRandomKey()
	if err != nil {
		t.Fatalf("NewRandomKey: %v", err)
	}
	k.Zero()

	if !k.Zeroed() {
		t.Fatal("Zeroed reported false after Zero")
	}
	if _, err := SealSecret(k, ref(), []byte("x")); !errors.Is(err, ErrKeyZeroed) {
		t.Fatalf("sealing with a zeroed key returned %v", err)
	}
	k.Zero() // must stay safe when called twice, so defer is usable
}

func TestZeroWipesSharedBacking(t *testing.T) {
	k := mustKey(t)
	raw := k.Bytes()
	k.Zero()

	for i, b := range raw {
		if b != 0 {
			t.Fatalf("key material survived Zero at offset %d", i)
		}
	}
}

func TestRejectsMalformedBlobs(t *testing.T) {
	dek := mustKey(t)
	for name, blob := range map[string][]byte{
		"empty":       {},
		"too short":   make([]byte, blobFixed-1),
		"bad version": append([]byte{0xFF}, make([]byte, blobFixed)...),
		"header only": make([]byte, blobFixed),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenSecret(dek, ref(), blob); err == nil {
				t.Fatal("malformed blob was accepted")
			}
		})
	}
}

func TestSecretRefValidation(t *testing.T) {
	dek := mustKey(t)
	for name, r := range map[string]SecretRef{
		"no project":    {Name: "x", Version: 1},
		"no path":       {ProjectID: "maison", Version: 1},
		"zero version":  {ProjectID: "maison", Name: "x", Version: 0},
		"negative ver.": {ProjectID: "maison", Name: "x", Version: -1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := SealSecret(dek, r, []byte("x")); err == nil {
				t.Fatal("invalid reference was accepted")
			}
		})
	}
}

func BenchmarkSealSecret(b *testing.B) {
	dek, _ := NewRandomKey()
	defer dek.Zero()
	value := []byte("a-fairly-typical-api-token-value-0123456789")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := SealSecret(dek, ref(), value); err != nil {
			b.Fatal(err)
		}
	}
}
