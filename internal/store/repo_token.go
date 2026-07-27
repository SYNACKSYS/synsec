package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ServiceToken authenticates a machine: a Home Assistant instance, a script, a
// container. Only the hash of its secret half is stored.
type ServiceToken struct {
	ID          string
	Name        string
	ProjectID   string
	Env         string
	CanWrite    bool
	ExpiresAt   time.Time // zero means it never expires
	IPAllowlist []string  // empty means any address
	// Secrets narrows the token to a few entries by name. Empty means the whole
	// vault, which is what a token without a stated scope has always meant.
	Secrets   []string
	CreatedAt time.Time
	CreatedBy   string
	LastUsedAt  time.Time
	RevokedAt   time.Time
}

// Live reports whether the token may still be used at the given moment.
func (t ServiceToken) Live(now time.Time) bool {
	if !t.RevokedAt.IsZero() {
		return false
	}
	return t.ExpiresAt.IsZero() || t.ExpiresAt.After(now)
}

// Allows reports whether the token may act on a vault with the given intent.
func (t ServiceToken) Allows(projectID, env string, write bool) bool {
	if t.ProjectID != projectID || t.Env != env {
		return false
	}
	return !write || t.CanWrite
}

// AllowsSecret reports whether the token covers one entry.
//
// An empty scope covers the vault. A stated scope covers exactly what it
// names and nothing else: a secret created later does not join it on its own,
// because a credential that quietly widens is the one nobody re-reads.
func (t ServiceToken) AllowsSecret(name string) bool {
	if len(t.Secrets) == 0 {
		return true
	}
	for _, allowed := range t.Secrets {
		if allowed == name {
			return true
		}
	}
	return false
}

// AllowsIP reports whether an address may present this token. An empty
// allowlist means any address.
//
// This pins the credential; secret_networks pins the secret. The two are
// deliberately separate: a token belongs to a device, a restriction belongs to
// what is being protected, and either may exist without the other.
func (t ServiceToken) AllowsIP(ip string) bool {
	return AddressAllowed(t.IPAllowlist, ip)
}

// CreateServiceToken stores a token against the hash of its secret, filling in
// ID and CreatedAt. The caller keeps the plaintext to show once and discard.
func (db *DB) CreateServiceToken(ctx context.Context, t *ServiceToken, secretHash []byte) error {
	switch {
	case t.Name == "":
		return fmt.Errorf("store: a token needs a name")
	case t.ProjectID == "" || t.Env == "":
		return fmt.Errorf("store: a token needs a vault and an environment")
	case len(secretHash) == 0:
		return fmt.Errorf("store: a token needs a secret hash")
	}

	if t.ID == "" {
		id, err := NewID()
		if err != nil {
			return err
		}
		t.ID = id
	}
	created := time.Now()

	if _, err := db.ExecContext(ctx, `
		INSERT INTO service_tokens (id, name, secret_hash, project_id, env,
		                            can_write, expires_at, ip_allowlist, created_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, secretHash, t.ProjectID, t.Env,
		boolToInt(t.CanWrite), nullableUnix(t.ExpiresAt),
		strings.Join(t.IPAllowlist, ","), created.Unix(), t.CreatedBy,
	); err != nil {
		return fmt.Errorf("store: creating token %q: %w", t.Name, err)
	}
	if err := db.SetTokenSecrets(ctx, t.ID, t.Secrets); err != nil {
		return err
	}

	t.CreatedAt = created
	return nil
}

// SetTokenSecrets replaces a token's scope. An empty list opens the whole
// vault again.
func (db *DB) SetTokenSecrets(ctx context.Context, tokenID string, names []string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: narrowing token %q: %w", tokenID, err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM token_secrets WHERE token_id = ?`, tokenID); err != nil {
		return fmt.Errorf("store: clearing scope of token %q: %w", tokenID, err)
	}
	for _, name := range names {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO token_secrets (token_id, secret_name) VALUES (?, ?)`,
			tokenID, name); err != nil {
			return fmt.Errorf("store: adding %q to token %q: %w", name, tokenID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: narrowing token %q: %w", tokenID, err)
	}
	return nil
}

// tokenSecrets reads one token's scope.
func (db *DB) tokenSecrets(ctx context.Context, tokenID string) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT secret_name FROM token_secrets WHERE token_id = ? ORDER BY secret_name`,
		tokenID)
	if err != nil {
		return nil, fmt.Errorf("store: reading scope of token %q: %w", tokenID, err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: scanning token scope: %w", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating token scope: %w", err)
	}
	return out, nil
}

// tokenScopes reads the scope of every token of a vault in one query, so
// listing does not turn into one round trip per device.
func (db *DB) tokenScopes(ctx context.Context, projectID string) (map[string][]string, error) {
	query := `
		SELECT ts.token_id, ts.secret_name
		FROM token_secrets ts
		JOIN service_tokens t ON t.id = ts.token_id`
	args := []any{}
	if projectID != "" {
		query += ` WHERE t.project_id = ?`
		args = append(args, projectID)
	}
	query += ` ORDER BY ts.secret_name`

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: reading token scopes: %w", err)
	}
	defer rows.Close()

	out := make(map[string][]string)
	for rows.Next() {
		var tokenID, name string
		if err := rows.Scan(&tokenID, &name); err != nil {
			return nil, fmt.Errorf("store: scanning token scope: %w", err)
		}
		out[tokenID] = append(out[tokenID], name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating token scopes: %w", err)
	}
	return out, nil
}

// ServiceToken returns a token and the hash of its secret, for verification.
//
// Revoked and expired tokens are returned rather than hidden: the caller needs
// to tell "this token was revoked" apart from "this token never existed" when
// writing the audit entry, even though both answers to the client are the same.
func (db *DB) ServiceToken(ctx context.Context, id string) (ServiceToken, []byte, error) {
	var (
		t          ServiceToken
		secretHash []byte
		canWrite   int
		allowlist  string
		createdAt  int64
		expiresAt  sql.NullInt64
		lastUsedAt sql.NullInt64
		revokedAt  sql.NullInt64
	)
	err := db.QueryRowContext(ctx, `
		SELECT id, name, secret_hash, project_id, env, can_write,
		       expires_at, ip_allowlist, created_at, created_by, last_used_at, revoked_at
		FROM service_tokens WHERE id = ?`, id,
	).Scan(&t.ID, &t.Name, &secretHash, &t.ProjectID, &t.Env, &canWrite,
		&expiresAt, &allowlist, &createdAt, &t.CreatedBy, &lastUsedAt, &revokedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return ServiceToken{}, nil, fmt.Errorf("store: token %q: %w", id, ErrNotFound)
	}
	if err != nil {
		return ServiceToken{}, nil, fmt.Errorf("store: reading token %q: %w", id, err)
	}

	t.CanWrite = canWrite != 0
	t.IPAllowlist = splitAllowlist(allowlist)
	t.CreatedAt = time.Unix(createdAt, 0)
	t.ExpiresAt = fromNullableUnix(expiresAt)
	t.LastUsedAt = fromNullableUnix(lastUsedAt)
	t.RevokedAt = fromNullableUnix(revokedAt)

	if t.Secrets, err = db.tokenSecrets(ctx, t.ID); err != nil {
		return ServiceToken{}, nil, err
	}
	return t, secretHash, nil
}

// ListServiceTokens returns the tokens of one vault, newest first. Pass an
// empty projectID to list every token on the server.
func (db *DB) ListServiceTokens(ctx context.Context, projectID string) ([]ServiceToken, error) {
	query := `
		SELECT id, name, project_id, env, can_write, expires_at,
		       ip_allowlist, created_at, created_by, last_used_at, revoked_at
		FROM service_tokens`
	args := []any{}
	if projectID != "" {
		query += ` WHERE project_id = ?`
		args = append(args, projectID)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing tokens: %w", err)
	}
	defer rows.Close()

	var out []ServiceToken
	for rows.Next() {
		var (
			t          ServiceToken
			canWrite   int
			allowlist  string
			createdAt  int64
			expiresAt  sql.NullInt64
			lastUsedAt sql.NullInt64
			revokedAt  sql.NullInt64
		)
		if err := rows.Scan(&t.ID, &t.Name, &t.ProjectID, &t.Env, &canWrite,
			&expiresAt, &allowlist, &createdAt, &t.CreatedBy, &lastUsedAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("store: scanning token: %w", err)
		}
		t.CanWrite = canWrite != 0
		t.IPAllowlist = splitAllowlist(allowlist)
		t.CreatedAt = time.Unix(createdAt, 0)
		t.ExpiresAt = fromNullableUnix(expiresAt)
		t.LastUsedAt = fromNullableUnix(lastUsedAt)
		t.RevokedAt = fromNullableUnix(revokedAt)
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating tokens: %w", err)
	}

	scopes, err := db.tokenScopes(ctx, projectID)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Secrets = scopes[out[i].ID]
	}
	return out, nil
}

// RevokeServiceToken disables a token without deleting it, so the audit log
// keeps pointing at something that still has a name.
func (db *DB) RevokeServiceToken(ctx context.Context, id string, when time.Time) error {
	res, err := db.ExecContext(ctx,
		`UPDATE service_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		when.Unix(), id)
	if err != nil {
		return fmt.Errorf("store: revoking token %q: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: token %q is unknown or already revoked: %w", id, ErrNotFound)
	}
	return nil
}

// TouchServiceToken records that a token was used, which is what makes "this
// device stopped talking to me three weeks ago" visible in the interface.
func (db *DB) TouchServiceToken(ctx context.Context, id string, when time.Time) error {
	if _, err := db.ExecContext(ctx,
		`UPDATE service_tokens SET last_used_at = ? WHERE id = ?`, when.Unix(), id); err != nil {
		return fmt.Errorf("store: recording use of token %q: %w", id, err)
	}
	return nil
}

// DeleteServiceToken removes a token for good.
func (db *DB) DeleteServiceToken(ctx context.Context, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM service_tokens WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: deleting token %q: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: token %q: %w", id, ErrNotFound)
	}
	return nil
}

func nullableUnix(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

func fromNullableUnix(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return time.Unix(n.Int64, 0)
}

func splitAllowlist(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
