package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"synsec/internal/crypto"
)

func testCredentials() Credentials {
	return Credentials{
		Hash:   bytes.Repeat([]byte{0xA5}, 32),
		Salt:   bytes.Repeat([]byte{0x5A}, 16),
		Params: crypto.DefaultArgon2,
	}
}

func newUser(t *testing.T, db *DB, username string) User {
	t.Helper()
	u := User{Username: username, DisplayName: username, IsAdmin: true}
	if err := db.CreateUser(context.Background(), &u, testCredentials()); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func TestUserRoundTrip(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	u := newUser(t, db, "cyril")

	if u.ID == "" || u.CreatedAt.IsZero() {
		t.Fatal("CreateUser did not fill in ID and CreatedAt")
	}

	byID, err := db.User(ctx, u.ID)
	if err != nil {
		t.Fatalf("User: %v", err)
	}
	if !byID.IsAdmin {
		t.Fatal("the admin flag did not survive the round trip")
	}
	if !byID.LastLoginAt.IsZero() {
		t.Fatal("a brand new user already has a last sign-in")
	}

	byName, err := db.UserByUsername(ctx, "CYRIL")
	if err != nil {
		t.Fatalf("UserByUsername is case sensitive: %v", err)
	}
	if byName.ID != u.ID {
		t.Fatal("UserByUsername returned a different account")
	}

	if _, err := db.User(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user returned %v, want ErrNotFound", err)
	}
}

func TestUserCredentialsRoundTrip(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	u := newUser(t, db, "cyril")

	got, err := db.UserCredentials(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserCredentials: %v", err)
	}
	want := testCredentials()
	if !bytes.Equal(got.Hash, want.Hash) || !bytes.Equal(got.Salt, want.Salt) {
		t.Fatal("the stored verifier changed across the round trip")
	}
	if got.Params != want.Params {
		t.Fatalf("Argon2 parameters came back as %+v, want %+v", got.Params, want.Params)
	}

	// Parameters travel with the hash so an old password still verifies under
	// the cost it was created with.
	updated := Credentials{Hash: bytes.Repeat([]byte{1}, 32), Salt: bytes.Repeat([]byte{2}, 16), Params: crypto.LowMemoryArgon2}
	if err := db.SetUserCredentials(ctx, u.ID, updated); err != nil {
		t.Fatalf("SetUserCredentials: %v", err)
	}
	got, err = db.UserCredentials(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserCredentials: %v", err)
	}
	if got.Params != crypto.LowMemoryArgon2 {
		t.Fatalf("updated parameters came back as %+v", got.Params)
	}
}

func TestCreateUserRejectsEmptyPassword(t *testing.T) {
	db := openTemp(t)
	u := User{Username: "cyril"}
	if err := db.CreateUser(context.Background(), &u, Credentials{}); err == nil {
		t.Fatal("a user was created without a password")
	}
}

func TestCountAndTouchUser(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()

	if n, _ := db.CountUsers(ctx); n != 0 {
		t.Fatalf("a fresh database holds %d users, want 0", n)
	}
	u := newUser(t, db, "cyril")
	if n, _ := db.CountUsers(ctx); n != 1 {
		t.Fatalf("after one CreateUser the count is %d, want 1", n)
	}

	when := time.Now().Truncate(time.Second)
	if err := db.TouchUserLogin(ctx, u.ID, when); err != nil {
		t.Fatalf("TouchUserLogin: %v", err)
	}
	got, err := db.User(ctx, u.ID)
	if err != nil {
		t.Fatalf("User: %v", err)
	}
	if !got.LastLoginAt.Equal(when) {
		t.Fatalf("last sign-in is %v, want %v", got.LastLoginAt, when)
	}
}

func TestSessionLifecycle(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	u := newUser(t, db, "cyril")
	now := time.Now()

	hash := bytes.Repeat([]byte{0x11}, 32)
	s := Session{UserID: u.ID, ExpiresAt: now.Add(time.Hour), UserAgent: "Firefox", IP: "192.168.1.10"}
	if err := db.CreateSession(ctx, &s, hash); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if s.ID == "" {
		t.Fatal("CreateSession did not fill in the identifier")
	}

	found, err := db.SessionByTokenHash(ctx, hash, now)
	if err != nil {
		t.Fatalf("SessionByTokenHash: %v", err)
	}
	if found.UserID != u.ID || found.IP != "192.168.1.10" {
		t.Fatalf("session came back as %+v", found)
	}

	if err := db.DeleteSession(ctx, s.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := db.SessionByTokenHash(ctx, hash, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a deleted session returned %v, want ErrNotFound", err)
	}
}

// A stale cookie has to behave exactly like no cookie at all.
func TestExpiredSessionIsInvisible(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	u := newUser(t, db, "cyril")
	now := time.Now()

	hash := bytes.Repeat([]byte{0x22}, 32)
	s := Session{UserID: u.ID, ExpiresAt: now.Add(-time.Minute)}
	if err := db.CreateSession(ctx, &s, hash); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if _, err := db.SessionByTokenHash(ctx, hash, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired session was returned (%v)", err)
	}

	n, err := db.PurgeExpiredSessions(ctx, now)
	if err != nil {
		t.Fatalf("PurgeExpiredSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("purged %d sessions, want 1", n)
	}
}

func TestSessionRequiresExpiry(t *testing.T) {
	db := openTemp(t)
	u := newUser(t, db, "cyril")

	s := Session{UserID: u.ID}
	if err := db.CreateSession(context.Background(), &s, bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("a session without an expiry was accepted")
	}
}

// Changing a password has to sign every browser out.
func TestDeleteUserSessions(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	u := newUser(t, db, "cyril")
	now := time.Now()

	for i := byte(0); i < 3; i++ {
		s := Session{UserID: u.ID, ExpiresAt: now.Add(time.Hour)}
		if err := db.CreateSession(ctx, &s, bytes.Repeat([]byte{i + 1}, 32)); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}
	if live, _ := db.ListSessions(ctx, u.ID, now); len(live) != 3 {
		t.Fatalf("%d live sessions, want 3", len(live))
	}

	if err := db.DeleteUserSessions(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUserSessions: %v", err)
	}
	if live, _ := db.ListSessions(ctx, u.ID, now); len(live) != 0 {
		t.Fatalf("%d sessions survived, want 0", len(live))
	}
}

func TestDeletingUserRemovesSessions(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	u := newUser(t, db, "cyril")

	s := Session{UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}
	if err := db.CreateSession(ctx, &s, bytes.Repeat([]byte{9}, 32)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := db.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	var remaining int
	db.QueryRow(`SELECT count(*) FROM sessions`).Scan(&remaining)
	if remaining != 0 {
		t.Fatalf("%d sessions outlived their user", remaining)
	}
}

func newToken(t *testing.T, db *DB, p Project, name string) ServiceToken {
	t.Helper()
	tok := ServiceToken{
		Name:      name,
		ProjectID: p.ID,
		Env:       DefaultEnvironment,
	}
	if err := db.CreateServiceToken(context.Background(), &tok, bytes.Repeat([]byte{0x33}, 32)); err != nil {
		t.Fatalf("CreateServiceToken: %v", err)
	}
	return tok
}

func TestServiceTokenRoundTrip(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	tok := newToken(t, db, p, "Home Assistant")

	got, hash, err := db.ServiceToken(ctx, tok.ID)
	if err != nil {
		t.Fatalf("ServiceToken: %v", err)
	}
	if got.Name != "Home Assistant" || got.ProjectID != p.ID {
		t.Fatalf("token came back as %+v", got)
	}
	if !bytes.Equal(hash, bytes.Repeat([]byte{0x33}, 32)) {
		t.Fatal("the stored secret hash changed")
	}
	if !got.ExpiresAt.IsZero() {
		t.Fatal("a token with no expiry came back with one")
	}
	if !got.Live(time.Now()) {
		t.Fatal("a fresh token is not live")
	}
}

func TestRevokedTokenIsNotLive(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	tok := newToken(t, db, p, "Home Assistant")
	now := time.Now()

	if err := db.RevokeServiceToken(ctx, tok.ID, now); err != nil {
		t.Fatalf("RevokeServiceToken: %v", err)
	}

	got, _, err := db.ServiceToken(ctx, tok.ID)
	if err != nil {
		t.Fatalf("a revoked token vanished instead of being marked: %v", err)
	}
	if got.Live(now) {
		t.Fatal("a revoked token is still live")
	}

	// Revoking twice must not silently look like success.
	if err := db.RevokeServiceToken(ctx, tok.ID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revocation returned %v, want ErrNotFound", err)
	}
}

func TestExpiredTokenIsNotLive(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	now := time.Now()

	tok := ServiceToken{
		Name: "temporaire", ProjectID: p.ID, Env: DefaultEnvironment,
		ExpiresAt: now.Add(-time.Minute),
	}
	if err := db.CreateServiceToken(ctx, &tok, bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("CreateServiceToken: %v", err)
	}

	got, _, err := db.ServiceToken(ctx, tok.ID)
	if err != nil {
		t.Fatalf("ServiceToken: %v", err)
	}
	if got.Live(now) {
		t.Fatal("an expired token is still live")
	}
}

func TestTokenScopeChecksVaultEnvironmentAndIntent(t *testing.T) {
	readOnly := ServiceToken{ProjectID: "p1", Env: "prod"}

	if readOnly.Allows("p2", "prod", false) {
		t.Error("a token reached another vault")
	}
	if readOnly.Allows("p1", "dev", false) {
		t.Error("a token reached another environment")
	}
	if readOnly.Allows("p1", "prod", true) {
		t.Error("a read-only token was allowed to write")
	}
	if !readOnly.Allows("p1", "prod", false) {
		t.Error("a token was refused a read on its own vault")
	}

	writer := ServiceToken{ProjectID: "p1", Env: "prod", CanWrite: true}
	if !writer.Allows("p1", "prod", true) {
		t.Error("a writing token was refused a write")
	}
}

func TestTokenIPAllowlist(t *testing.T) {
	open := ServiceToken{}
	if !open.AllowsIP("192.168.1.10") {
		t.Error("an empty allowlist should accept any address")
	}

	restricted := ServiceToken{IPAllowlist: []string{"192.168.1.10", "10.0.0.0/8"}}
	for _, ip := range []string{"192.168.1.10", "10.4.3.2"} {
		if !restricted.AllowsIP(ip) {
			t.Errorf("%s should be allowed", ip)
		}
	}
	for _, ip := range []string{"192.168.1.11", "172.16.0.1", "", "not-an-address"} {
		if restricted.AllowsIP(ip) {
			t.Errorf("%s should be refused", ip)
		}
	}
}

func TestTokenAllowlistSurvivesStorage(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")

	tok := ServiceToken{
		Name: "HA", ProjectID: p.ID, Env: DefaultEnvironment,
		IPAllowlist: []string{"192.168.1.10", "10.0.0.0/8"},
	}
	if err := db.CreateServiceToken(ctx, &tok, bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("CreateServiceToken: %v", err)
	}

	got, _, err := db.ServiceToken(ctx, tok.ID)
	if err != nil {
		t.Fatalf("ServiceToken: %v", err)
	}
	if len(got.IPAllowlist) != 2 || got.IPAllowlist[0] != "192.168.1.10" {
		t.Fatalf("allowlist came back as %v", got.IPAllowlist)
	}
}

func TestDeletingVaultRemovesItsTokens(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")
	newToken(t, db, p, "Home Assistant")

	if err := db.DeleteProject(ctx, p.ID); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}

	var remaining int
	db.QueryRow(`SELECT count(*) FROM service_tokens`).Scan(&remaining)
	if remaining != 0 {
		t.Fatalf("%d tokens outlived their vault", remaining)
	}
}

func TestAuditAppendAndFilter(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	base := time.Now().Add(-time.Hour).Truncate(time.Second)

	entries := []AuditEntry{
		{At: base, ActorKind: ActorUser, ActorID: "u1", ActorLabel: "cyril", Action: "secret.read", Target: "mqtt_user"},
		{At: base.Add(time.Minute), ActorKind: ActorToken, ActorID: "t1", ActorLabel: "HA", Action: "secret.read", Target: "mqtt_password"},
		{At: base.Add(2 * time.Minute), ActorKind: ActorUser, ActorID: "u1", ActorLabel: "cyril", Action: "secret.write", Target: "mqtt_user"},
	}
	for _, e := range entries {
		if err := db.AppendAudit(ctx, e); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}

	all, err := db.ListAudit(ctx, AuditFilter{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d entries, want 3", len(all))
	}
	if all[0].Action != "secret.write" {
		t.Fatalf("newest entry is %q, want secret.write", all[0].Action)
	}

	byActor, err := db.ListAudit(ctx, AuditFilter{ActorKind: ActorToken})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(byActor) != 1 || byActor[0].ActorLabel != "HA" {
		t.Fatalf("filtering by actor kind gave %+v", byActor)
	}

	// Reads are recorded too: without them the log could not answer what an
	// attacker looked at.
	reads, err := db.ListAudit(ctx, AuditFilter{Action: "secret.read"})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(reads) != 2 {
		t.Fatalf("got %d reads, want 2", len(reads))
	}

	recent, err := db.ListAudit(ctx, AuditFilter{Since: base.Add(90 * time.Second)})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(recent) != 1 {
		t.Fatalf("filtering by time gave %d entries, want 1", len(recent))
	}

	limited, err := db.ListAudit(ctx, AuditFilter{Limit: 2})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("the limit returned %d entries, want 2", len(limited))
	}
}

func TestAuditRequiresAnAction(t *testing.T) {
	db := openTemp(t)
	if err := db.AppendAudit(context.Background(), AuditEntry{ActorKind: ActorUser}); err == nil {
		t.Fatal("an audit entry without an action was accepted")
	}
}

// The audit log must outlive what it describes, so deleting a vault cannot
// take its history with it.
func TestAuditSurvivesTheVaultItDescribes(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p := newVault(t, db, "Maison")

	if err := db.AppendAudit(ctx, AuditEntry{
		ActorKind: ActorUser, ActorID: "u1", Action: "vault.create", Target: p.ID,
	}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if err := db.DeleteProject(ctx, p.ID); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}

	all, err := db.ListAudit(ctx, AuditFilter{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("%d audit entries survived the vault, want 1", len(all))
	}
}
