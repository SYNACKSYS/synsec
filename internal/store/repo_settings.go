package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// UserSetting reads one preference, returning the fallback when the account has
// never chosen anything.
//
// A missing row is not an error: a preference that was never set is simply the
// default, and every caller would otherwise have to say so itself.
func (db *DB) UserSetting(ctx context.Context, userID, key, fallback string) (string, error) {
	var value string
	err := db.QueryRowContext(ctx,
		`SELECT value FROM user_settings WHERE user_id = ? AND key = ?`,
		userID, key).Scan(&value)

	if errors.Is(err, sql.ErrNoRows) {
		return fallback, nil
	}
	if err != nil {
		return fallback, fmt.Errorf("store: reading setting %q: %w", key, err)
	}
	return value, nil
}

// SetUserSetting stores one preference, replacing any previous value.
func (db *DB) SetUserSetting(ctx context.Context, userID, key, value string) error {
	if _, err := db.ExecContext(ctx, `
		INSERT INTO user_settings (user_id, key, value) VALUES (?, ?, ?)
		ON CONFLICT (user_id, key) DO UPDATE SET value = excluded.value`,
		userID, key, value); err != nil {
		return fmt.Errorf("store: saving setting %q: %w", key, err)
	}
	return nil
}

// ServerSetting reads one server-wide setting, returning the fallback when
// nobody has ever set it.
func (db *DB) ServerSetting(ctx context.Context, key, fallback string) (string, error) {
	var value string
	err := db.QueryRowContext(ctx,
		`SELECT value FROM server_settings WHERE key = ?`, key).Scan(&value)

	if errors.Is(err, sql.ErrNoRows) {
		return fallback, nil
	}
	if err != nil {
		return fallback, fmt.Errorf("store: reading server setting %q: %w", key, err)
	}
	return value, nil
}

// SetServerSetting stores one, replacing any previous value.
func (db *DB) SetServerSetting(ctx context.Context, key, value string) error {
	if _, err := db.ExecContext(ctx, `
		INSERT INTO server_settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
		key, value); err != nil {
		return fmt.Errorf("store: saving server setting %q: %w", key, err)
	}
	return nil
}
