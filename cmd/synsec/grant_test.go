package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"synsec/internal/auth"
	"synsec/internal/crypto"
	"synsec/internal/store"
	"synsec/internal/vault"
)

// Giving access from the command line.
//
// The command line runs next to the database rather than behind the web
// server, which is exactly why the grants must ask the same questions: who is
// doing this, and may they. Otherwise reaching the data directory is a shorter
// road to somebody else's vault than logging in.

const testPassword = "un-mot-de-passe-de-test"

// cliFixture is a prepared data directory: an initialised vault, a few
// accounts, one project, and a pipe standing in for the terminal.
type cliFixture struct {
	dir string
	db  *store.DB
	p   store.Project
}

func newCLIFixture(t *testing.T) *cliFixture {
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

	f := &cliFixture{dir: dir, db: db}
	owner := f.addUser(t, "cyril")

	p, err := m.CreateVault(ctx, "Maison", "", owner.ID)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	// As both creation paths do: owning the row and holding the role are two
	// different records, and only the second one grants anything.
	if err := db.SetVaultMember(ctx, p.ID, owner.ID, store.RoleManager, owner.Username); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}
	f.p = p
	return f
}

// addUser creates an account with a deliberately cheap password profile: these
// tests verify a password on every call and the default 64 MiB would dominate
// the run.
func (f *cliFixture) addUser(t *testing.T, name string) store.User {
	t.Helper()
	cred, err := auth.HashPasswordWith(testPassword, crypto.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1})
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	u := store.User{Username: name, DisplayName: name}
	if err := f.db.CreateUser(context.Background(), &u, cred); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

// typePassword answers the next prompts with the given lines, the way a
// scripted session does.
func (f *cliFixture) typePassword(t *testing.T, lines ...string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	go func() {
		for _, l := range lines {
			w.WriteString(l + "\n") //nolint:errcheck // the reader is what is under test
		}
		w.Close()
	}()

	original := os.Stdin
	os.Stdin = r
	pipedOnce = sync.Once{}
	piped = nil
	t.Cleanup(func() {
		os.Stdin = original
		pipedOnce = sync.Once{}
		piped = nil
	})
}

func (f *cliFixture) role(t *testing.T, userID string) store.Role {
	t.Helper()
	role, err := f.db.VaultRole(context.Background(), f.p.ID, userID)
	if err != nil {
		t.Fatalf("VaultRole: %v", err)
	}
	return role
}

// The widest grant there is: a whole vault, gestion included. Without a
// password it must not happen at all.
func TestSharingAVaultAsksWhoIsAsking(t *testing.T) {
	f := newCLIFixture(t)
	alice := f.addUser(t, "alice")

	err := runVaultShare([]string{"-data", f.dir, f.p.Name, "alice", "-role", "gestion"})
	if err == nil {
		t.Fatal("un coffre a été partagé sans aucune identité")
	}
	if !strings.Contains(err.Error(), "compte") {
		t.Errorf("le refus n'explique pas quoi faire : %v", err)
	}
	if role := f.role(t, alice.ID); role != store.RoleNone {
		t.Fatalf("alice a reçu %s malgré le refus", role)
	}
}

// And having a password is not enough: it has to be the password of somebody
// who manages the vault.
func TestSharingAVaultNeedsGestion(t *testing.T) {
	f := newCLIFixture(t)
	alice := f.addUser(t, "alice")
	bob := f.addUser(t, "bob")
	if err := f.db.SetVaultMember(context.Background(), f.p.ID, bob.ID, store.RoleWriter, "test"); err != nil {
		t.Fatalf("SetVaultMember: %v", err)
	}

	f.typePassword(t, testPassword)
	err := runVaultShare([]string{"-data", f.dir, f.p.Name, "alice", "-role", "gestion", "-user", "bob"})
	if err == nil {
		t.Fatal("un rédacteur a partagé le coffre qu'il ne gère pas")
	}
	if role := f.role(t, alice.ID); role != store.RoleNone {
		t.Fatalf("alice a reçu %s d'un rédacteur", role)
	}
}

func TestAWrongPasswordSharesNothing(t *testing.T) {
	f := newCLIFixture(t)
	alice := f.addUser(t, "alice")

	f.typePassword(t, "pas le bon")
	if err := runVaultShare([]string{"-data", f.dir, f.p.Name, "alice", "-user", "cyril"}); err == nil {
		t.Fatal("un mot de passe incorrect a partagé le coffre")
	}
	if role := f.role(t, alice.ID); role != store.RoleNone {
		t.Fatalf("alice a reçu %s avec un mot de passe incorrect", role)
	}
}

// The gestionnaire, on the other hand, gets through - and the journal records
// their name rather than the word "cli".
func TestAManagerSharesAndIsNamedInTheJournal(t *testing.T) {
	f := newCLIFixture(t)
	alice := f.addUser(t, "alice")

	f.typePassword(t, testPassword)
	if err := runVaultShare([]string{"-data", f.dir, f.p.Name, "alice", "-role", "lecture", "-user", "cyril"}); err != nil {
		t.Fatalf("le gestionnaire a été refusé : %v", err)
	}
	if role := f.role(t, alice.ID); role != store.RoleReader {
		t.Fatalf("alice a %s, attendu lecture", role)
	}

	entries, err := f.db.ListAudit(context.Background(), store.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "vault.share" {
			found = true
			if e.ActorLabel != "cyril" {
				t.Errorf("le journal attribue le partage à %q", e.ActorLabel)
			}
		}
	}
	if !found {
		t.Error("le partage d'un coffre n'a rien écrit au journal")
	}
}

// Changing a token's scope moves what a remote credential reaches, so it is
// held like the creation was.
func TestChangingATokenScopeAsksToo(t *testing.T) {
	f := newCLIFixture(t)
	ctx := context.Background()

	id, err := store.NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	_, hash, err := auth.NewServiceToken(id)
	if err != nil {
		t.Fatalf("NewServiceToken: %v", err)
	}
	tok := store.ServiceToken{
		ID: id, Name: "domotique", ProjectID: f.p.ID,
		Env: store.DefaultEnvironment, Secrets: []string{"mqtt"}, CreatedBy: "cyril",
	}
	if err := f.db.CreateServiceToken(ctx, &tok, hash); err != nil {
		t.Fatalf("CreateServiceToken: %v", err)
	}

	// Widening it to the whole vault, with nothing but the identifier.
	if err := runTokenScope([]string{"-data", f.dir, id, ""}); err == nil {
		t.Fatal("la portée d'un token a été changée sans identité")
	}
	after, _, err := f.db.ServiceToken(ctx, id)
	if err != nil {
		t.Fatalf("ServiceToken: %v", err)
	}
	if len(after.Secrets) != 1 {
		t.Fatalf("la portée a bougé : %v", after.Secrets)
	}

	// Reading it back stays free: it changes nothing, and a password prompt
	// on a report is how people learn to type it without looking.
	if err := runTokenScope([]string{"-data", f.dir, id}); err != nil {
		t.Fatalf("lire une portée a échoué : %v", err)
	}
}
