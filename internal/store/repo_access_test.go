package store

import (
	"context"
	"errors"
	"testing"
)

func TestRoleOrdering(t *testing.T) {
	if !RoleManager.AtLeast(RoleWriter) || !RoleWriter.AtLeast(RoleReader) {
		t.Fatal("the roles are not ordered from reader to manager")
	}
	if RoleReader.AtLeast(RoleWriter) {
		t.Fatal("a reader was treated as a writer")
	}
	if RoleNone.AtLeast(RoleReader) {
		t.Fatal("no access was treated as read access")
	}
	if RoleNone.Valid() {
		t.Fatal("no access was accepted as a storable role")
	}

	// Access is additive: a share must never take a right away.
	if Higher(RoleReader, RoleWriter) != RoleWriter {
		t.Fatal("Higher did not return the stronger role")
	}
	if Higher(RoleManager, RoleReader) != RoleManager {
		t.Fatal("Higher downgraded a manager")
	}
}

func TestVaultMembership(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	u := newUser(t, db, "cyril")

	if role, _ := db.VaultRole(ctx, p.ID, u.ID); role != RoleNone {
		t.Fatalf("a stranger holds %q on a vault", role)
	}

	if err := db.SetVaultMember(ctx, p.ID, u.ID, RoleReader, "test"); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}
	if role, _ := db.VaultRole(ctx, p.ID, u.ID); role != RoleReader {
		t.Fatalf("the granted role came back as %q", role)
	}

	// Granting again changes the role rather than failing.
	if err := db.SetVaultMember(ctx, p.ID, u.ID, RoleManager, "test"); err != nil {
		t.Fatalf("regranting: %v", err)
	}
	if role, _ := db.VaultRole(ctx, p.ID, u.ID); role != RoleManager {
		t.Fatalf("the role was not raised: %q", role)
	}

	if err := db.RemoveVaultMember(ctx, p.ID, u.ID); err != nil {
		t.Fatalf("RemoveVaultMember: %v", err)
	}
	if role, _ := db.VaultRole(ctx, p.ID, u.ID); role != RoleNone {
		t.Fatalf("access survived revocation: %q", role)
	}
	if err := db.RemoveVaultMember(ctx, p.ID, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking twice returned %v, want ErrNotFound", err)
	}
}

func TestSetVaultMemberRejectsBadRole(t *testing.T) {
	db := openTemp(t)
	p := newVault(t, db, "Maison")
	u := newUser(t, db, "cyril")

	if err := db.SetVaultMember(context.Background(), p.ID, u.ID, RoleNone, "test"); err == nil {
		t.Fatal("an empty role was accepted")
	}
}

// A vault someone holds no role on must be absent from their list, not merely
// read-only: its name alone can say more than its contents.
func TestListVaultsForUserShowsOnlyGranted(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	maison := newVault(t, db, "Maison")
	newVault(t, db, "Bureau")
	u := newUser(t, db, "cyril")

	if vaults, _ := db.ListVaultsForUser(ctx, u.ID); len(vaults) != 0 {
		t.Fatalf("a user with no membership sees %d vaults", len(vaults))
	}

	if err := db.SetVaultMember(ctx, maison.ID, u.ID, RoleReader, "test"); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}
	vaults, err := db.ListVaultsForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListVaultsForUser: %v", err)
	}
	if len(vaults) != 1 || vaults[0].Name != "Maison" {
		t.Fatalf("the visible vaults are %+v", vaults)
	}
	// The role travels with the vault: the interface separates what someone
	// manages from what was opened to them, and asking again per vault would
	// mean one query per row.
	if vaults[0].Role != RoleReader {
		t.Fatalf("the vault came back with role %q, want reader", vaults[0].Role)
	}

	db.SetVaultMember(ctx, maison.ID, u.ID, RoleManager, "test")
	if vaults, _ := db.ListVaultsForUser(ctx, u.ID); vaults[0].Role != RoleManager {
		t.Fatalf("the raised role is %q", vaults[0].Role)
	}
}

func TestListVaultMembers(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	cyril := newUser(t, db, "cyril")
	alice := newUser(t, db, "alice")

	db.SetVaultMember(ctx, p.ID, cyril.ID, RoleManager, "test")
	db.SetVaultMember(ctx, p.ID, alice.ID, RoleReader, "cyril")

	members, err := db.ListVaultMembers(ctx, p.ID)
	if err != nil {
		t.Fatalf("ListVaultMembers: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("got %d members, want 2", len(members))
	}
	// Alphabetical, so alice comes first.
	if members[0].Username != "alice" || members[0].Role != RoleReader {
		t.Fatalf("the first member is %+v", members[0])
	}
	if members[0].GrantedBy != "cyril" {
		t.Fatalf("the grantor was not recorded: %q", members[0].GrantedBy)
	}
}

func TestSecretSharing(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	u := newUser(t, db, "alice")

	loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "mqtt_password"}
	secret, err := db.PutSecret(ctx, loc, "", "cyril", sealing("s3cr3t", nil))
	if err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	if role, _ := db.SecretShareRole(ctx, secret.ID, u.ID); role != RoleNone {
		t.Fatalf("a stranger holds %q on a secret", role)
	}
	if err := db.SetSecretShare(ctx, secret.ID, u.ID, RoleReader, "cyril"); err != nil {
		t.Fatalf("SetSecretShare: %v", err)
	}
	if role, _ := db.SecretShareRole(ctx, secret.ID, u.ID); role != RoleReader {
		t.Fatalf("the share came back as %q", role)
	}

	if err := db.RemoveSecretShare(ctx, secret.ID, u.ID); err != nil {
		t.Fatalf("RemoveSecretShare: %v", err)
	}
	if role, _ := db.SecretShareRole(ctx, secret.ID, u.ID); role != RoleNone {
		t.Fatalf("the share survived revocation: %q", role)
	}
}

// Destroying a secret and its history stays a vault-level right, so a share
// can never be granted at manager level.
func TestSecretShareRefusesManager(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	u := newUser(t, db, "alice")

	loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "mqtt_password"}
	secret, _ := db.PutSecret(ctx, loc, "", "cyril", sealing("s3cr3t", nil))

	if err := db.SetSecretShare(ctx, secret.ID, u.ID, RoleManager, "cyril"); err == nil {
		t.Fatal("a secret was shared at manager level")
	}
}

// A share on a vault someone already belongs to would show the same secret
// twice and invite them to think it is two different things.
func TestListSharedSecretsExcludesVaultMembers(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	u := newUser(t, db, "alice")

	loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "mqtt_password"}
	secret, _ := db.PutSecret(ctx, loc, "", "cyril", sealing("s3cr3t", nil))
	if err := db.SetSecretShare(ctx, secret.ID, u.ID, RoleWriter, "cyril"); err != nil {
		t.Fatalf("SetSecretShare: %v", err)
	}

	shared, err := db.ListSharedSecrets(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListSharedSecrets: %v", err)
	}
	if len(shared) != 1 {
		t.Fatalf("got %d shared secrets, want 1", len(shared))
	}
	if shared[0].Name != "mqtt_password" || shared[0].ProjectName != "Maison" {
		t.Fatalf("the shared secret is %+v", shared[0])
	}
	if shared[0].Role != RoleWriter {
		t.Fatalf("the share role is %q", shared[0].Role)
	}

	// Once she belongs to the vault, the individual share is no longer worth
	// listing separately.
	db.SetVaultMember(ctx, p.ID, u.ID, RoleReader, "cyril")
	shared, err = db.ListSharedSecrets(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListSharedSecrets: %v", err)
	}
	if len(shared) != 0 {
		t.Fatalf("a vault member still sees %d separately shared secrets", len(shared))
	}
}

func TestDeletingSecretRemovesItsShares(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	u := newUser(t, db, "alice")

	loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "mqtt_password"}
	secret, _ := db.PutSecret(ctx, loc, "", "cyril", sealing("s3cr3t", nil))
	db.SetSecretShare(ctx, secret.ID, u.ID, RoleReader, "cyril")

	if err := db.DeleteSecret(ctx, loc); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	var remaining int
	db.QueryRow(`SELECT count(*) FROM secret_shares`).Scan(&remaining)
	if remaining != 0 {
		t.Fatalf("%d shares outlived their secret", remaining)
	}
}

func TestDeletingUserRemovesTheirAccess(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	u := newUser(t, db, "alice")
	db.SetVaultMember(ctx, p.ID, u.ID, RoleReader, "cyril")

	if err := db.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	var remaining int
	db.QueryRow(`SELECT count(*) FROM vault_members`).Scan(&remaining)
	if remaining != 0 {
		t.Fatalf("%d memberships outlived their user", remaining)
	}
}

// Deleting the only manager of a vault would strand it: administrators no
// longer see what was not shared with them, so nobody could rescue it.
func TestSoleManagerVaults(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	maison := newVault(t, db, "Maison")
	bureau := newVault(t, db, "Bureau")
	cyril := newUser(t, db, "cyril")
	alice := newUser(t, db, "alice")

	db.SetVaultMember(ctx, maison.ID, cyril.ID, RoleManager, "test")
	db.SetVaultMember(ctx, maison.ID, alice.ID, RoleReader, "test")

	// Bureau has two managers, so neither is on their own.
	db.SetVaultMember(ctx, bureau.ID, cyril.ID, RoleManager, "test")
	db.SetVaultMember(ctx, bureau.ID, alice.ID, RoleManager, "test")

	stranded, err := db.SoleManagerVaults(ctx, cyril.ID)
	if err != nil {
		t.Fatalf("SoleManagerVaults: %v", err)
	}
	if len(stranded) != 1 || stranded[0].Name != "Maison" {
		t.Fatalf("got %+v, want only Maison", stranded)
	}

	// A reader is never the manager of anything.
	if stranded, _ := db.SoleManagerVaults(ctx, alice.ID); len(stranded) != 0 {
		t.Fatalf("a co-manager was reported as the sole one: %+v", stranded)
	}
}

func TestSecretMetaTouchesNoCiphertext(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")

	loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "mqtt_password"}
	if _, err := db.PutSecret(ctx, loc, "", "cyril", sealing("s3cr3t", nil)); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	meta, err := db.SecretMeta(ctx, loc)
	if err != nil {
		t.Fatalf("SecretMeta: %v", err)
	}
	if meta.ID == "" || meta.CurrentVersion != 1 || meta.Name != "mqtt_password" {
		t.Fatalf("the metadata is %+v", meta)
	}

	missing := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "/absent"}
	if _, err := db.SecretMeta(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a missing secret returned %v, want ErrNotFound", err)
	}
}
