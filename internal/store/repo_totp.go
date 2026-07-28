package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// TOTPSecret returns an account's shared secret, empty when the second factor
// is not set up.
//
// Scanned as bytes because the column was declared BLOB in the very first
// schema, long before anything wrote to it. Its affinity is not worth a
// migration; what goes in is text and what comes out is the same text.
func (db *DB) TOTPSecret(ctx context.Context, userID string) (string, error) {
	var secret []byte
	err := db.QueryRowContext(ctx,
		`SELECT totp_secret FROM users WHERE id = ?`, userID).Scan(&secret)

	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("store: user %q: %w", userID, ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("store: reading second factor of %q: %w", userID, err)
	}
	return string(secret), nil
}

// SetTOTPSecret turns the second factor on, replacing any recovery codes with
// the ones given.
//
// Both in one transaction: an account left with a new secret and the old
// codes, or with codes and no secret, is an account somebody is locked out of.
func (db *DB) SetTOTPSecret(ctx context.Context, userID, secret string, recoveryCodes []string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: enabling second factor: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET totp_secret = ? WHERE id = ?`, secret, userID); err != nil {
		return fmt.Errorf("store: storing second factor of %q: %w", userID, err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM totp_recovery WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("store: clearing recovery codes of %q: %w", userID, err)
	}
	for _, code := range recoveryCodes {
		sum := sha256.Sum256([]byte(code))
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO totp_recovery (user_id, code_hash) VALUES (?, ?)`,
			userID, sum[:]); err != nil {
			return fmt.Errorf("store: storing a recovery code of %q: %w", userID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: enabling second factor: %w", err)
	}
	return nil
}

// ClearTOTP turns the second factor off and forgets the recovery codes.
func (db *DB) ClearTOTP(ctx context.Context, userID string) error {
	return db.SetTOTPSecret(ctx, userID, "", nil)
}

// UseRecoveryCode spends a code, reporting whether it was valid and unused.
//
// The update is the check: marking it used in one statement means two requests
// racing on the same code cannot both succeed.
func (db *DB) UseRecoveryCode(ctx context.Context, userID, code string, now time.Time) (bool, error) {
	sum := sha256.Sum256([]byte(code))

	res, err := db.ExecContext(ctx,
		`UPDATE totp_recovery SET used_at = ?
		 WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
		now.Unix(), userID, sum[:])
	if err != nil {
		return false, fmt.Errorf("store: spending a recovery code of %q: %w", userID, err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: spending a recovery code of %q: %w", userID, err)
	}
	return n == 1, nil
}

// CountUnusedRecoveryCodes says how many are left, so the interface can warn
// before there are none.
func (db *DB) CountUnusedRecoveryCodes(ctx context.Context, userID string) (int, error) {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM totp_recovery WHERE user_id = ? AND used_at IS NULL`,
		userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: counting recovery codes of %q: %w", userID, err)
	}
	return n, nil
}
