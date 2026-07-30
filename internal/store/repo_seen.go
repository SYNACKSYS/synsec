package store

import (
	"context"
	"fmt"
	"time"
)

// What the server has already seen, so it can recognise what it has not.
//
// Only used to decide whether an event deserves a notification. Nothing here
// grants or refuses access: an address nobody has seen before is a reason to
// tell somebody, never a reason to close a door on its own. A rule that locked
// out an account on a new address would fire the first time its owner opened
// the interface from a phone on mobile data.

// AddressStatus says what noticing an address amounts to.
type AddressStatus int

const (
	// AddressKnown: this actor has used this address before.
	AddressKnown AddressStatus = iota
	// AddressFirst: the first address ever seen for this actor. Recorded
	// quietly - a device has to speak from somewhere the first time, and
	// announcing it would mean an alert for every token ever created.
	AddressFirst
	// AddressNew: this actor is known, this address is not. The one worth
	// saying out loud.
	AddressNew
)

// NoteAddress records that an actor was seen at an address, and reports what
// that means.
//
// Deliberately one call rather than a read and a write: two callers noticing
// the same new address at the same moment would otherwise both announce it.
func (db *DB) NoteAddress(ctx context.Context, actorKind, actorID, ip string, at time.Time) (AddressStatus, error) {
	if actorID == "" || ip == "" {
		return AddressKnown, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return AddressKnown, fmt.Errorf("store: noting address: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rolled back only if Commit did not run

	var known, here int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(ip = ?), 0)
		  FROM seen_addresses WHERE actor_kind = ? AND actor_id = ?`,
		ip, actorKind, actorID).Scan(&known, &here); err != nil {
		return AddressKnown, fmt.Errorf("store: reading known addresses: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO seen_addresses (actor_kind, actor_id, ip, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (actor_kind, actor_id, ip) DO UPDATE SET last_seen = excluded.last_seen`,
		actorKind, actorID, ip, at.Unix(), at.Unix()); err != nil {
		return AddressKnown, fmt.Errorf("store: saving seen address: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return AddressKnown, fmt.Errorf("store: saving seen address: %w", err)
	}

	switch {
	case here > 0:
		return AddressKnown, nil
	case known == 0:
		return AddressFirst, nil
	default:
		return AddressNew, nil
	}
}

// ForgetAddresses drops what was remembered about one actor, so a revoked
// token or a deleted account leaves nothing behind to compare against.
func (db *DB) ForgetAddresses(ctx context.Context, actorKind, actorID string) error {
	if _, err := db.ExecContext(ctx,
		`DELETE FROM seen_addresses WHERE actor_kind = ? AND actor_id = ?`,
		actorKind, actorID); err != nil {
		return fmt.Errorf("store: forgetting addresses: %w", err)
	}
	return nil
}
