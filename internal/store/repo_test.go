package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"synsec/internal/crypto"
)

func newVault(t *testing.T, db *DB, name string) Project {
	t.Helper()
	p := Project{Name: name, WrappedDEK: []byte("wrapped")}
	if err := db.CreateProject(context.Background(), &p); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	return p
}

// sealing returns a SealFunc that records which version it was asked for.
func sealing(value string, gotVersion *int64) SealFunc {
	return func(version int64) ([]byte, error) {
		if gotVersion != nil {
			*gotVersion = version
		}
		return []byte(fmt.Sprintf("sealed(%s,v%d)", value, version)), nil
	}
}

func TestCreateProjectMakesDefaultEnvironment(t *testing.T) {
	db := openTemp(t)
	p := newVault(t, db, "Maison")

	if p.ID == "" || p.CreatedAt.IsZero() {
		t.Fatal("CreateProject did not fill in ID and CreatedAt")
	}

	envs, err := db.ListEnvironments(context.Background(), p.ID)
	if err != nil {
		t.Fatalf("ListEnvironments: %v", err)
	}
	if len(envs) != 1 || envs[0].Slug != DefaultEnvironment {
		t.Fatalf("got %d environments, want one named %q", len(envs), DefaultEnvironment)
	}
}

// A vault whose environment failed to insert would silently accept no secrets,
// so the two writes must share a transaction.
func TestCreateProjectIsAtomic(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	newVault(t, db, "Maison")

	dup := Project{Name: "Maison", WrappedDEK: []byte("wrapped")}
	if err := db.CreateProject(ctx, &dup); err == nil {
		t.Fatal("two vaults with the same name were both accepted")
	}

	var envs int
	if err := db.QueryRow(`SELECT count(*) FROM environments`).Scan(&envs); err != nil {
		t.Fatalf("counting environments: %v", err)
	}
	if envs != 1 {
		t.Fatalf("%d environments after a failed vault creation, want 1", envs)
	}
}

func TestProjectLookup(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")

	byID, err := db.Project(ctx, p.ID)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if byID.Name != "Maison" {
		t.Fatalf("got vault %q, want Maison", byID.Name)
	}

	byName, err := db.ProjectByName(ctx, "maison")
	if err != nil {
		t.Fatalf("ProjectByName is case sensitive: %v", err)
	}
	if byName.ID != p.ID {
		t.Fatal("ProjectByName returned a different vault")
	}

	if _, err := db.Project(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing vault returned %v, want ErrNotFound", err)
	}
}

func TestPutSecretVersionsFromOne(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "mqtt_password"}

	var sealed int64
	first, err := db.PutSecret(ctx, loc, "", "cyril", sealing("a", &sealed))
	if err != nil {
		t.Fatalf("first PutSecret: %v", err)
	}
	if first.CurrentVersion != 1 || sealed != 1 {
		t.Fatalf("first write produced version %d (sealed as %d), want 1", first.CurrentVersion, sealed)
	}

	second, err := db.PutSecret(ctx, loc, "", "cyril", sealing("b", &sealed))
	if err != nil {
		t.Fatalf("second PutSecret: %v", err)
	}
	if second.CurrentVersion != 2 || sealed != 2 {
		t.Fatalf("second write produced version %d (sealed as %d), want 2", second.CurrentVersion, sealed)
	}
	if second.ID != first.ID {
		t.Fatal("rewriting a secret created a second row instead of a new version")
	}
}

// The seal callback must receive the version the ciphertext will be stored
// under: the version is authenticated, so a mismatch makes the value
// permanently unreadable.
func TestSealFuncSeesTheStoredVersion(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "mqtt_password"}

	for want := int64(1); want <= 3; want++ {
		s, err := db.PutSecret(ctx, loc, "", "cyril", func(version int64) ([]byte, error) {
			if version != want {
				t.Fatalf("seal called with version %d, want %d", version, want)
			}
			return []byte{byte(version)}, nil
		})
		if err != nil {
			t.Fatalf("PutSecret: %v", err)
		}
		if s.CurrentVersion != want {
			t.Fatalf("stored version %d, want %d", s.CurrentVersion, want)
		}
	}
}

// If sealing fails, nothing at all must be written - least of all a secrets
// row whose current_version points at a version that does not exist.
func TestFailedSealWritesNothing(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "mqtt_password"}

	boom := errors.New("no key")
	if _, err := db.PutSecret(ctx, loc, "", "cyril", func(int64) ([]byte, error) {
		return nil, boom
	}); !errors.Is(err, boom) {
		t.Fatalf("PutSecret returned %v, want the sealing error", err)
	}

	var secrets, versions int
	db.QueryRow(`SELECT count(*) FROM secrets`).Scan(&secrets)
	db.QueryRow(`SELECT count(*) FROM secret_versions`).Scan(&versions)
	if secrets != 0 || versions != 0 {
		t.Fatalf("a failed seal left %d secrets and %d versions behind", secrets, versions)
	}
}

func TestSecretReadsCurrentVersion(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "mqtt_password"}

	db.PutSecret(ctx, loc, "", "cyril", sealing("old", nil))
	db.PutSecret(ctx, loc, "", "cyril", sealing("new", nil))

	got, blob, err := db.Secret(ctx, loc)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	if got.CurrentVersion != 2 {
		t.Fatalf("read version %d, want 2", got.CurrentVersion)
	}
	if !bytes.Contains(blob, []byte("new")) {
		t.Fatalf("read blob %q, want the newest one", blob)
	}

	old, err := db.SecretVersionBlob(ctx, got.ID, 1)
	if err != nil {
		t.Fatalf("SecretVersionBlob: %v", err)
	}
	if !bytes.Contains(old, []byte("old")) {
		t.Fatalf("version 1 holds %q, want the original value", old)
	}
}

// A vault lists everything it holds, alphabetically, and nothing else.
func TestListSecretsReturnsTheWholeVault(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	other := newVault(t, db, "Bureau")

	for _, name := range []string{"zigbee_key", "mqtt_user", "mqtt_password"} {
		loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: name}
		if _, err := db.PutSecret(ctx, loc, "", "cyril", sealing("v", nil)); err != nil {
			t.Fatalf("PutSecret %s: %v", name, err)
		}
	}
	elsewhere := SecretLocation{ProjectID: other.ID, Env: DefaultEnvironment, Name: "autre"}
	db.PutSecret(ctx, elsewhere, "", "cyril", sealing("v", nil))

	all, err := db.ListSecrets(ctx, p.ID, DefaultEnvironment)
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d secrets, want the vault's 3", len(all))
	}
	// Alphabetical, so the listing reads the same way twice running.
	if all[0].Name != "mqtt_password" || all[2].Name != "zigbee_key" {
		t.Fatalf("the listing is out of order: %+v", all)
	}
	// And no value is carried: the metadata table exists so a listing costs
	// nothing in cryptography and leaks nothing if it is logged.
	for _, s := range all {
		if s.Comment != "" && s.CurrentVersion == 0 {
			t.Fatalf("unexpected content in %+v", s)
		}
	}
}

// The naming rule is what replaced the hierarchy: an entry is one token,
// usable as written in a script or a configuration file.
func TestSecretNamesAreValidated(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")

	for _, bad := range []string{
		"", " ", "mqtt/password", "mqtt password", "mot de passe",
		"mqtt.password", "mqtt%password", strings.Repeat("a", MaxSecretNameLength+1),
	} {
		loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: bad}
		if _, err := db.PutSecret(ctx, loc, "", "cyril", sealing("v", nil)); err == nil {
			t.Errorf("the name %q was accepted", bad)
		}
	}

	for _, good := range []string{"mqtt_password", "MQTT-Password", "cle2", "a"} {
		loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: good}
		if _, err := db.PutSecret(ctx, loc, "", "cyril", sealing("v", nil)); err != nil {
			t.Errorf("the name %q was refused: %v", good, err)
		}
	}
}

func TestListVersionsNewestFirst(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "mqtt_user"}

	db.PutSecret(ctx, loc, "", "cyril", sealing("a", nil))
	s, _ := db.PutSecret(ctx, loc, "", "alice", sealing("b", nil))

	versions, err := db.ListVersions(ctx, s.ID)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("got %d versions, want 2", len(versions))
	}
	if versions[0].Version != 2 || versions[0].CreatedBy != "alice" {
		t.Fatalf("newest version is %+v, want version 2 by alice", versions[0])
	}
}

func TestDeleteSecretRemovesHistory(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "mqtt_user"}

	db.PutSecret(ctx, loc, "", "cyril", sealing("a", nil))
	db.PutSecret(ctx, loc, "", "cyril", sealing("b", nil))

	if err := db.DeleteSecret(ctx, loc); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	var versions int
	db.QueryRow(`SELECT count(*) FROM secret_versions`).Scan(&versions)
	if versions != 0 {
		t.Fatalf("%d versions survived the deletion of their secret", versions)
	}
	if err := db.DeleteSecret(ctx, loc); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting a missing secret returned %v, want ErrNotFound", err)
	}
}

func TestKeySlotRoundTrip(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()

	rec := KeySlotRecord{
		Slot: crypto.KeySlot{
			ID:     "primary",
			Kind:   crypto.SlotPassphrase,
			Salt:   []byte("0123456789abcdef"),
			Params: crypto.DefaultArgon2,
			Blob:   []byte("wrapped-root"),
		},
	}
	if err := db.SaveKeySlot(ctx, rec); err != nil {
		t.Fatalf("SaveKeySlot: %v", err)
	}

	got, err := db.KeySlotByKind(ctx, crypto.SlotPassphrase)
	if err != nil {
		t.Fatalf("KeySlotByKind: %v", err)
	}
	if got.Slot.ID != "primary" || !bytes.Equal(got.Slot.Blob, rec.Slot.Blob) {
		t.Fatalf("round trip gave %+v", got.Slot)
	}
	if got.Slot.Params != crypto.DefaultArgon2 {
		t.Fatalf("Argon2 parameters came back as %+v, want %+v", got.Slot.Params, crypto.DefaultArgon2)
	}

	if _, err := db.KeySlotByKind(ctx, crypto.SlotMachine); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing slot returned %v, want ErrNotFound", err)
	}
}

// Losing every slot means losing every secret, so the count that guards the
// setup wizard has to be right.
func TestCountKeySlots(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()

	for _, kind := range []crypto.SlotKind{crypto.SlotPassphrase, crypto.SlotRecovery, crypto.SlotMachine} {
		rec := KeySlotRecord{Slot: crypto.KeySlot{ID: string(kind), Kind: kind, Blob: []byte("x")}}
		if err := db.SaveKeySlot(ctx, rec); err != nil {
			t.Fatalf("SaveKeySlot(%s): %v", kind, err)
		}
	}

	n, err := db.CountKeySlots(ctx)
	if err != nil {
		t.Fatalf("CountKeySlots: %v", err)
	}
	if n != 3 {
		t.Fatalf("counted %d slots, want 3", n)
	}
}

func TestMetaRoundTrip(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()

	if err := db.SetMeta(ctx, "unseal.provider", []byte("dpapi")); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := db.SetMeta(ctx, "unseal.provider", []byte("keyfile")); err != nil {
		t.Fatalf("SetMeta overwrite: %v", err)
	}

	got, err := db.Meta(ctx, "unseal.provider")
	if err != nil {
		t.Fatalf("Meta: %v", err)
	}
	if string(got) != "keyfile" {
		t.Fatalf("got %q, want keyfile", got)
	}

	if _, err := db.Meta(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing key returned %v, want ErrNotFound", err)
	}
}

func TestNewIDIsRandom(t *testing.T) {
	seen := make(map[string]bool, 500)
	for i := 0; i < 500; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatalf("NewID: %v", err)
		}
		if seen[id] {
			t.Fatalf("NewID repeated %q", id)
		}
		seen[id] = true
	}
}
