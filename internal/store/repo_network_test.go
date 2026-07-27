package store

import (
	"context"
	"errors"
	"testing"
)

func TestParseNetworkCanonicalises(t *testing.T) {
	cases := map[string]string{
		"192.168.1.72":   "192.168.1.72",
		" 192.168.1.72 ": "192.168.1.72",
		"192.168.1.0/24": "192.168.1.0/24",
		"10.0.0.0/8":     "10.0.0.0/8",
		"::1":            "::1",
		"fd00::/8":       "fd00::/8",
		// A block written from a host address is stored masked, so its written
		// form cannot suggest a single machine.
		"192.168.1.72/24": "192.168.1.0/24",
	}
	for raw, want := range cases {
		got, err := ParseNetwork(raw)
		if err != nil {
			t.Errorf("ParseNetwork(%q): %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("ParseNetwork(%q) = %q, want %q", raw, got, want)
		}
	}

	for _, bad := range []string{"", "   ", "pas une adresse", "192.168.1.999", "192.168.1.0/64"} {
		if _, err := ParseNetwork(bad); err == nil {
			t.Errorf("ParseNetwork(%q) was accepted", bad)
		}
	}
}

func TestAddressAllowed(t *testing.T) {
	// The restriction is opt-in: nothing listed means nothing restricted.
	if !AddressAllowed(nil, "192.168.1.72") {
		t.Fatal("an empty list refused an address")
	}

	list := []string{"192.168.1.72", "10.0.0.0/8"}
	for _, ip := range []string{"192.168.1.72", "10.4.3.2", "10.255.255.255"} {
		if !AddressAllowed(list, ip) {
			t.Errorf("%s should be allowed", ip)
		}
	}
	for _, ip := range []string{"192.168.1.73", "172.16.0.1", "", "pas une adresse"} {
		if AddressAllowed(list, ip) {
			t.Errorf("%s should be refused", ip)
		}
	}
}

// An IPv4 client arriving over a dual-stack socket presents itself as
// ::ffff:192.168.1.72, which would match no IPv4 rule as written.
func TestAddressAllowedUnmapsIPv4(t *testing.T) {
	if !AddressAllowed([]string{"192.168.1.72"}, "::ffff:192.168.1.72") {
		t.Fatal("a mapped IPv4 address was refused by an IPv4 rule")
	}
	if !AddressAllowed([]string{"192.168.1.0/24"}, "::ffff:192.168.1.72") {
		t.Fatal("a mapped IPv4 address was refused by an IPv4 block")
	}
}

func pinnedSecret(t *testing.T, db *DB) (Project, Secret) {
	t.Helper()
	ctx := context.Background()

	p := newVault(t, db, "Maison")
	loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "zigbee_cle"}
	secret, err := db.PutSecret(ctx, loc, "", "cyril", sealing("s3cr3t", nil))
	if err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	return p, secret
}

func TestSecretNetworkLifecycle(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	_, secret := pinnedSecret(t, db)

	// Unrestricted by default.
	allowed, err := db.SecretAllowsAddress(ctx, secret.ID, "203.0.113.9")
	if err != nil {
		t.Fatalf("SecretAllowsAddress: %v", err)
	}
	if !allowed {
		t.Fatal("an unpinned secret refused an address")
	}

	if err := db.AddSecretNetwork(ctx, secret.ID, "192.168.1.72", "cyril"); err != nil {
		t.Fatalf("AddSecretNetwork: %v", err)
	}

	if allowed, _ := db.SecretAllowsAddress(ctx, secret.ID, "192.168.1.72"); !allowed {
		t.Fatal("the pinned address was refused")
	}
	if allowed, _ := db.SecretAllowsAddress(ctx, secret.ID, "192.168.1.73"); allowed {
		t.Fatal("an address outside the list was allowed")
	}
	// Including the server itself: the restriction is not a network-only rule.
	if allowed, _ := db.SecretAllowsAddress(ctx, secret.ID, "127.0.0.1"); allowed {
		t.Fatal("loopback was allowed implicitly")
	}

	// Adding the same entry twice must not create a duplicate.
	if err := db.AddSecretNetwork(ctx, secret.ID, "192.168.1.72", "alice"); err != nil {
		t.Fatalf("re-adding: %v", err)
	}
	networks, err := db.ListSecretNetworks(ctx, secret.ID)
	if err != nil {
		t.Fatalf("ListSecretNetworks: %v", err)
	}
	if len(networks) != 1 {
		t.Fatalf("%d entries after adding the same address twice", len(networks))
	}

	if err := db.RemoveSecretNetwork(ctx, secret.ID, "192.168.1.72"); err != nil {
		t.Fatalf("RemoveSecretNetwork: %v", err)
	}
	if allowed, _ := db.SecretAllowsAddress(ctx, secret.ID, "203.0.113.9"); !allowed {
		t.Fatal("the secret stayed restricted after the last entry was removed")
	}
	if err := db.RemoveSecretNetwork(ctx, secret.ID, "192.168.1.72"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removing twice returned %v, want ErrNotFound", err)
	}
}

// The same address written two ways must not become two entries, or removing
// one would silently leave the other in force.
func TestSecretNetworkStoresCanonicalForm(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	_, secret := pinnedSecret(t, db)

	if err := db.AddSecretNetwork(ctx, secret.ID, "192.168.1.72/24", "cyril"); err != nil {
		t.Fatalf("AddSecretNetwork: %v", err)
	}
	if err := db.AddSecretNetwork(ctx, secret.ID, "192.168.1.0/24", "cyril"); err != nil {
		t.Fatalf("AddSecretNetwork: %v", err)
	}

	networks, err := db.ListSecretNetworks(ctx, secret.ID)
	if err != nil {
		t.Fatalf("ListSecretNetworks: %v", err)
	}
	if len(networks) != 1 || networks[0].Network != "192.168.1.0/24" {
		t.Fatalf("the stored entries are %+v", networks)
	}
}

func TestNetworksForVault(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p, pinned := pinnedSecret(t, db)

	// A second secret, left unrestricted.
	free := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "mqtt_user"}
	if _, err := db.PutSecret(ctx, free, "", "cyril", sealing("bob", nil)); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	db.AddSecretNetwork(ctx, pinned.ID, "192.168.1.72", "cyril")
	db.AddSecretNetwork(ctx, pinned.ID, "10.0.0.0/8", "cyril")

	all, err := db.NetworksForVault(ctx, p.ID, DefaultEnvironment)
	if err != nil {
		t.Fatalf("NetworksForVault: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("%d secrets reported as pinned, want 1", len(all))
	}
	if len(all[pinned.ID]) != 2 {
		t.Fatalf("the pinned secret has %d entries, want 2", len(all[pinned.ID]))
	}
	// An unpinned secret is absent from the map, and an absent key yields the
	// empty list that AddressAllowed treats as "no restriction".
	if !AddressAllowed(all["nexistepas"], "203.0.113.9") {
		t.Fatal("an unpinned secret was treated as restricted")
	}
}

func TestDeletingSecretRemovesItsNetworks(t *testing.T) {
	db := openTemp(t)
	ctx := context.Background()
	p, secret := pinnedSecret(t, db)

	db.AddSecretNetwork(ctx, secret.ID, "192.168.1.72", "cyril")

	loc := SecretLocation{ProjectID: p.ID, Env: DefaultEnvironment, Name: "zigbee_cle"}
	if err := db.DeleteSecret(ctx, loc); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	var remaining int
	db.QueryRow(`SELECT count(*) FROM secret_networks`).Scan(&remaining)
	if remaining != 0 {
		t.Fatalf("%d restrictions outlived their secret", remaining)
	}
}

// The token allowlist and the secret restriction share one matcher, so they
// cannot drift apart in how they read an address.
func TestTokenAllowlistUsesTheSameMatcher(t *testing.T) {
	tok := ServiceToken{IPAllowlist: []string{"10.0.0.0/8"}}

	if !tok.AllowsIP("10.4.3.2") || !tok.AllowsIP("::ffff:10.4.3.2") {
		t.Fatal("the token allowlist refused an address the secret matcher allows")
	}
	if tok.AllowsIP("192.168.1.1") {
		t.Fatal("the token allowlist accepted an address outside its block")
	}
	if !(ServiceToken{}).AllowsIP("192.168.1.1") {
		t.Fatal("an empty token allowlist refused an address")
	}
}
