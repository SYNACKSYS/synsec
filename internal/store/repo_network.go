package store

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// SecretNetwork is one address or block a secret may be read from.
type SecretNetwork struct {
	Network string
	AddedAt time.Time
	AddedBy string
}

// ParseNetwork validates an address or CIDR block and returns its canonical
// form.
//
// Canonicalising on the way in matters: stored as typed, "192.168.001.1" and
// "192.168.1.1" would sit in the list as two different entries meaning the
// same thing, and removing one would silently leave the other.
func ParseNetwork(raw string) (string, error) {
	entry := strings.TrimSpace(raw)
	if entry == "" {
		return "", fmt.Errorf("store: adresse vide")
	}

	if prefix, err := netip.ParsePrefix(entry); err == nil {
		// Masked so that 192.168.1.72/24 is stored as 192.168.1.0/24 rather
		// than as a block whose written form suggests a single host.
		return prefix.Masked().String(), nil
	}
	if addr, err := netip.ParseAddr(entry); err == nil {
		return addr.String(), nil
	}
	return "", fmt.Errorf("store: %q n'est ni une adresse IP ni un bloc CIDR", raw)
}

// AddressAllowed reports whether ip falls inside any of the entries.
//
// An empty list allows everything, which is what makes the restriction opt-in:
// a secret nobody pinned is readable from anywhere the caller is otherwise
// entitled to read it from.
func AddressAllowed(entries []string, ip string) bool {
	if len(entries) == 0 {
		return true
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		// An address that cannot be parsed cannot be shown to be allowed.
		return false
	}
	// An IPv4 address arriving over a dual-stack socket looks like
	// ::ffff:192.168.1.72, which would match no IPv4 rule as written.
	addr = addr.Unmap()

	for _, entry := range entries {
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			if prefix.Contains(addr) {
				return true
			}
			continue
		}
		if allowed, err := netip.ParseAddr(entry); err == nil && allowed.Unmap() == addr {
			return true
		}
	}
	return false
}

// AddSecretNetwork pins a secret to an address or block.
func (db *DB) AddSecretNetwork(ctx context.Context, secretID, raw, addedBy string) error {
	network, err := ParseNetwork(raw)
	if err != nil {
		return err
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO secret_networks (secret_id, network, added_at, added_by)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (secret_id, network) DO UPDATE SET
			added_at = excluded.added_at,
			added_by = excluded.added_by`,
		secretID, network, time.Now().Unix(), addedBy)
	if err != nil {
		return fmt.Errorf("store: pinning secret %s to %s: %w", secretID, network, err)
	}
	return nil
}

// RemoveSecretNetwork lifts one restriction.
func (db *DB) RemoveSecretNetwork(ctx context.Context, secretID, raw string) error {
	network, err := ParseNetwork(raw)
	if err != nil {
		return err
	}

	res, err := db.ExecContext(ctx,
		`DELETE FROM secret_networks WHERE secret_id = ? AND network = ?`, secretID, network)
	if err != nil {
		return fmt.Errorf("store: removing restriction %s: %w", network, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: restriction %s: %w", network, ErrNotFound)
	}
	return nil
}

// ListSecretNetworks returns the addresses a secret is pinned to, oldest
// first. An empty result means no restriction.
func (db *DB) ListSecretNetworks(ctx context.Context, secretID string) ([]SecretNetwork, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT network, added_at, added_by
		FROM secret_networks WHERE secret_id = ? ORDER BY added_at, network`, secretID)
	if err != nil {
		return nil, fmt.Errorf("store: listing restrictions: %w", err)
	}
	defer rows.Close()

	var out []SecretNetwork
	for rows.Next() {
		var (
			n       SecretNetwork
			addedAt int64
		)
		if err := rows.Scan(&n.Network, &addedAt, &n.AddedBy); err != nil {
			return nil, fmt.Errorf("store: scanning restriction: %w", err)
		}
		n.AddedAt = time.Unix(addedAt, 0)
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating restrictions: %w", err)
	}
	return out, nil
}

// SecretAllowsAddress reports whether one secret may be read from ip.
func (db *DB) SecretAllowsAddress(ctx context.Context, secretID, ip string) (bool, error) {
	networks, err := db.ListSecretNetworks(ctx, secretID)
	if err != nil {
		return false, err
	}

	entries := make([]string, 0, len(networks))
	for _, n := range networks {
		entries = append(entries, n.Network)
	}
	return AddressAllowed(entries, ip), nil
}

// NetworksForVault returns the restrictions of every pinned secret in a vault,
// keyed by secret identifier.
//
// The export endpoint hands back a whole vault at once and would otherwise ask
// the database once per secret; most households will have none of these rows
// at all, so a single query usually returns nothing and costs nothing.
func (db *DB) NetworksForVault(ctx context.Context, projectID, env string) (map[string][]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT n.secret_id, n.network
		FROM secret_networks n
		JOIN secrets s ON s.id = n.secret_id
		WHERE s.project_id = ? AND s.env = ?`, projectID, env)
	if err != nil {
		return nil, fmt.Errorf("store: listing vault restrictions: %w", err)
	}
	defer rows.Close()

	out := make(map[string][]string)
	for rows.Next() {
		var secretID, network string
		if err := rows.Scan(&secretID, &network); err != nil {
			return nil, fmt.Errorf("store: scanning restriction: %w", err)
		}
		out[secretID] = append(out[secretID], network)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating restrictions: %w", err)
	}
	return out, nil
}
