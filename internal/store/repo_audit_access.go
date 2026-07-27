package store

import (
	"context"
	"fmt"
	"time"
)

// AuditReader is an administrator the log was opened to.
type AuditReader struct {
	UserID      string
	Username    string
	DisplayName string
	GrantedAt   time.Time
	GrantedBy   string
}

// CanReadAudit reports whether an account may read the audit log.
//
// The account the server was set up with always can, and cannot have it taken
// away - otherwise a grant gone wrong would leave nobody able to see who did
// what, including the mistake itself.
func (db *DB) CanReadAudit(ctx context.Context, u User) (bool, error) {
	if u.IsRoot {
		return true, nil
	}
	// A grant follows the administrator flag: taking the flag away closes the
	// log with it, without anyone having to remember to revoke the grant too.
	if !u.IsAdmin {
		return false, nil
	}

	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM audit_readers WHERE user_id = ?`, u.ID).Scan(&n); err != nil {
		return false, fmt.Errorf("store: reading audit access of %q: %w", u.ID, err)
	}
	return n > 0, nil
}

// GrantAuditReader opens the log to an account.
func (db *DB) GrantAuditReader(ctx context.Context, userID, grantedBy string) error {
	if _, err := db.ExecContext(ctx, `
		INSERT INTO audit_readers (user_id, granted_at, granted_by) VALUES (?, ?, ?)
		ON CONFLICT (user_id) DO UPDATE SET granted_at = excluded.granted_at,
		                                    granted_by = excluded.granted_by`,
		userID, time.Now().Unix(), grantedBy); err != nil {
		return fmt.Errorf("store: granting audit access to %q: %w", userID, err)
	}
	return nil
}

// RevokeAuditReader closes the log again.
func (db *DB) RevokeAuditReader(ctx context.Context, userID string) error {
	if _, err := db.ExecContext(ctx,
		`DELETE FROM audit_readers WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("store: revoking audit access of %q: %w", userID, err)
	}
	return nil
}

// ListAuditReaders returns the accounts the log was opened to, oldest grant
// first. The account the server was set up with is not among them: it holds
// the access by nature, not by grant.
func (db *DB) ListAuditReaders(ctx context.Context) ([]AuditReader, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT r.user_id, u.username, u.display_name, r.granted_at, r.granted_by
		FROM audit_readers r
		JOIN users u ON u.id = r.user_id
		ORDER BY r.granted_at, u.username COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("store: listing audit readers: %w", err)
	}
	defer rows.Close()

	var out []AuditReader
	for rows.Next() {
		var (
			r         AuditReader
			grantedAt int64
		)
		if err := rows.Scan(&r.UserID, &r.Username, &r.DisplayName, &grantedAt, &r.GrantedBy); err != nil {
			return nil, fmt.Errorf("store: scanning audit reader: %w", err)
		}
		r.GrantedAt = time.Unix(grantedAt, 0)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating audit readers: %w", err)
	}
	return out, nil
}
