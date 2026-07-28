package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SecurityKey is a registered FIDO2 authenticator.
type SecurityKey struct {
	ID           string
	UserID       string
	CredentialID []byte
	PublicKey    []byte
	AAGUID       []byte
	SignCount    uint32
	Name         string
	CreatedAt    time.Time
	LastUsedAt   time.Time
}

// AddSecurityKey registers one against an account.
func (db *DB) AddSecurityKey(ctx context.Context, key *SecurityKey, now time.Time) error {
	id, err := NewID()
	if err != nil {
		return err
	}
	key.ID = id
	key.CreatedAt = now

	_, err = db.ExecContext(ctx,
		`INSERT INTO security_keys
		   (id, user_id, credential_id, public_key, aaguid, sign_count, name, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.UserID, key.CredentialID, key.PublicKey, key.AAGUID,
		int64(key.SignCount), key.Name, now.Unix())
	if err != nil {
		return fmt.Errorf("store: registering a security key: %w", err)
	}
	return nil
}

// SecurityKeys lists an account's keys, oldest first.
func (db *DB) SecurityKeys(ctx context.Context, userID string) ([]SecurityKey, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, user_id, credential_id, public_key, aaguid, sign_count,
		        name, created_at, last_used_at
		   FROM security_keys WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: listing the security keys of %q: %w", userID, err)
	}
	defer rows.Close()

	var out []SecurityKey
	for rows.Next() {
		key, err := scanSecurityKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing the security keys of %q: %w", userID, err)
	}
	return out, nil
}

// SecurityKeyByCredential finds the key a browser is answering with.
func (db *DB) SecurityKeyByCredential(ctx context.Context, credentialID []byte) (SecurityKey, error) {
	row := db.QueryRowContext(ctx,
		`SELECT id, user_id, credential_id, public_key, aaguid, sign_count,
		        name, created_at, last_used_at
		   FROM security_keys WHERE credential_id = ?`, credentialID)

	key, err := scanSecurityKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SecurityKey{}, fmt.Errorf("store: unknown credential: %w", ErrNotFound)
	}
	return key, err
}

// TouchSecurityKey records a successful use and the counter that came with it.
func (db *DB) TouchSecurityKey(ctx context.Context, id string, count uint32, now time.Time) error {
	_, err := db.ExecContext(ctx,
		`UPDATE security_keys SET sign_count = ?, last_used_at = ? WHERE id = ?`,
		int64(count), now.Unix(), id)
	if err != nil {
		return fmt.Errorf("store: recording the use of security key %q: %w", id, err)
	}
	return nil
}

// DeleteSecurityKey removes one, scoped to its owner so nobody can aim the
// identifier at somebody else's key.
func (db *DB) DeleteSecurityKey(ctx context.Context, userID, id string) error {
	res, err := db.ExecContext(ctx,
		`DELETE FROM security_keys WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return fmt.Errorf("store: removing security key %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: removing security key %q: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("store: security key %q: %w", id, ErrNotFound)
	}
	return nil
}

// HasSecondFactor reports whether an account carries any second factor at all.
//
// One query rather than two, because the answer is needed on every page when
// the server makes a second factor compulsory.
func (db *DB) HasSecondFactor(ctx context.Context, userID string) (bool, error) {
	var yes int
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT totp_secret FROM users WHERE id = ?), '') <> ''
		     OR EXISTS (SELECT 1 FROM security_keys WHERE user_id = ?)`,
		userID, userID).Scan(&yes)
	if err != nil {
		return false, fmt.Errorf("store: reading the second factor of %q: %w", userID, err)
	}
	return yes == 1, nil
}

// CountSecurityKeys says how many an account carries, which is what decides
// whether a password alone is still enough to sign in.
func (db *DB) CountSecurityKeys(ctx context.Context, userID string) (int, error) {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM security_keys WHERE user_id = ?`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: counting the security keys of %q: %w", userID, err)
	}
	return n, nil
}

func scanSecurityKey(row scanner) (SecurityKey, error) {
	var (
		key      SecurityKey
		count    int64
		created  int64
		lastUsed sql.NullInt64
	)
	err := row.Scan(&key.ID, &key.UserID, &key.CredentialID, &key.PublicKey,
		&key.AAGUID, &count, &key.Name, &created, &lastUsed)
	if err != nil {
		return SecurityKey{}, err
	}

	key.SignCount = uint32(count)
	key.CreatedAt = time.Unix(created, 0)
	if lastUsed.Valid {
		key.LastUsedAt = time.Unix(lastUsed.Int64, 0)
	}
	return key, nil
}
