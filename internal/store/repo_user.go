package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"synsec/internal/crypto"
)

// User is a person who signs in to the web interface.
type User struct {
	ID          string
	Username    string
	DisplayName string
	IsAdmin     bool
	// IsRoot marks the account the server was set up with. It is the only one
	// that reads the audit log without being granted it, and the only one that
	// can grant it.
	IsRoot      bool
	CreatedAt   time.Time
	LastLoginAt time.Time // zero if they have never signed in
}

// Credentials is a stored password verifier. The parameters travel with the
// hash so that raising the Argon2 cost later does not lock anyone out: each
// password is checked with the cost it was created under, and upgraded on the
// next successful sign-in.
type Credentials struct {
	Hash   []byte
	Salt   []byte
	Params crypto.Argon2Params
}

// CreateUser stores a new account and fills in ID and CreatedAt.
func (db *DB) CreateUser(ctx context.Context, u *User, cred Credentials) error {
	if err := ValidUsername(u.Username); err != nil {
		return err
	}
	if err := ValidLabel("le nom affiché", u.DisplayName); err != nil {
		return err
	}
	if u.Username == "" {
		return fmt.Errorf("store: a user needs a name")
	}
	if len(cred.Hash) == 0 || len(cred.Salt) == 0 {
		return fmt.Errorf("store: refusing to create user %q without a password", u.Username)
	}

	id, err := NewID()
	if err != nil {
		return err
	}
	params, err := json.Marshal(cred.Params)
	if err != nil {
		return fmt.Errorf("store: encoding password parameters: %w", err)
	}
	created := time.Now()

	if _, err := db.ExecContext(ctx, `
		INSERT INTO users (id, username, display_name, password_hash, password_salt,
		                   password_params, is_admin, is_root, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, u.Username, u.DisplayName, cred.Hash, cred.Salt, string(params),
		boolToInt(u.IsAdmin), boolToInt(u.IsRoot), created.Unix(),
	); err != nil {
		return fmt.Errorf("store: creating user %q: %w", u.Username, err)
	}

	u.ID, u.CreatedAt = id, created
	return nil
}

// userColumns is the projection every read of an account uses.
const userColumns = `id, username, display_name, is_admin, is_root, created_at, last_login_at`

// User looks an account up by identifier.
func (db *DB) User(ctx context.Context, id string) (User, error) {
	return scanUser(db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`, id), id)
}

// UserByUsername looks an account up by name, case-insensitively.
func (db *DB) UserByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE username = ? COLLATE NOCASE`,
		username), username)
}

func scanUser(row *sql.Row, what string) (User, error) {
	var (
		u         User
		isAdmin   int
		isRoot    int
		createdAt int64
		lastLogin sql.NullInt64
	)
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &isAdmin, &isRoot, &createdAt, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("store: user %q: %w", what, ErrNotFound)
	}
	if err != nil {
		return User{}, fmt.Errorf("store: reading user %q: %w", what, err)
	}

	u.IsAdmin = isAdmin != 0
	u.IsRoot = isRoot != 0
	u.CreatedAt = time.Unix(createdAt, 0)
	if lastLogin.Valid {
		u.LastLoginAt = time.Unix(lastLogin.Int64, 0)
	}
	return u, nil
}

// UserCredentials returns the stored password verifier.
func (db *DB) UserCredentials(ctx context.Context, id string) (Credentials, error) {
	var (
		cred   Credentials
		params string
	)
	err := db.QueryRowContext(ctx,
		`SELECT password_hash, password_salt, password_params FROM users WHERE id = ?`, id,
	).Scan(&cred.Hash, &cred.Salt, &params)

	if errors.Is(err, sql.ErrNoRows) {
		return Credentials{}, fmt.Errorf("store: user %q: %w", id, ErrNotFound)
	}
	if err != nil {
		return Credentials{}, fmt.Errorf("store: reading credentials of %q: %w", id, err)
	}
	if err := json.Unmarshal([]byte(params), &cred.Params); err != nil {
		return Credentials{}, fmt.Errorf("store: decoding password parameters of %q: %w", id, err)
	}
	return cred, nil
}

// SetUserCredentials replaces a password verifier.
func (db *DB) SetUserCredentials(ctx context.Context, id string, cred Credentials) error {
	if len(cred.Hash) == 0 || len(cred.Salt) == 0 {
		return fmt.Errorf("store: refusing to store an empty password for %q", id)
	}
	params, err := json.Marshal(cred.Params)
	if err != nil {
		return fmt.Errorf("store: encoding password parameters: %w", err)
	}

	res, err := db.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, password_salt = ?, password_params = ? WHERE id = ?`,
		cred.Hash, cred.Salt, string(params), id)
	if err != nil {
		return fmt.Errorf("store: updating password of %q: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: user %q: %w", id, ErrNotFound)
	}
	return nil
}

// ListUsers returns every account, alphabetically.
func (db *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+userColumns+` FROM users ORDER BY username COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("store: listing users: %w", err)
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var (
			u         User
			isAdmin   int
			isRoot    int
			createdAt int64
			lastLogin sql.NullInt64
		)
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &isAdmin, &isRoot,
			&createdAt, &lastLogin); err != nil {
			return nil, fmt.Errorf("store: scanning user: %w", err)
		}
		u.IsAdmin = isAdmin != 0
		u.IsRoot = isRoot != 0
		u.CreatedAt = time.Unix(createdAt, 0)
		if lastLogin.Valid {
			u.LastLoginAt = time.Unix(lastLogin.Int64, 0)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating users: %w", err)
	}
	return out, nil
}

// CountUsers reports how many accounts exist, which is how the setup wizard
// knows whether it still has work to do.
func (db *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: counting users: %w", err)
	}
	return n, nil
}

// TouchUserLogin records a successful sign-in.
func (db *DB) TouchUserLogin(ctx context.Context, id string, when time.Time) error {
	if _, err := db.ExecContext(ctx,
		`UPDATE users SET last_login_at = ? WHERE id = ?`, when.Unix(), id); err != nil {
		return fmt.Errorf("store: recording sign-in of %q: %w", id, err)
	}
	return nil
}

// DeleteUser removes an account and, by cascade, its sessions.
func (db *DB) DeleteUser(ctx context.Context, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: deleting user %q: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: user %q: %w", id, ErrNotFound)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
