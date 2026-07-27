package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Session is a signed-in browser.
//
// The token itself is never stored - only its hash - so a stolen database, or
// a backup that ends up somewhere it should not, does not hand over a set of
// live sessions.
type Session struct {
	ID         string
	UserID     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	UserAgent  string
	IP         string
}

// CreateSession stores a new session against the hash of its token, filling in
// ID, CreatedAt and LastSeenAt.
func (db *DB) CreateSession(ctx context.Context, s *Session, tokenHash []byte) error {
	if s.UserID == "" {
		return fmt.Errorf("store: a session needs a user")
	}
	if len(tokenHash) == 0 {
		return fmt.Errorf("store: a session needs a token hash")
	}
	if s.ExpiresAt.IsZero() {
		return fmt.Errorf("store: a session needs an expiry")
	}

	id, err := NewID()
	if err != nil {
		return err
	}
	now := time.Now()

	if _, err := db.ExecContext(ctx, `
		INSERT INTO sessions (id, token_hash, user_id, created_at, expires_at,
		                      last_seen_at, user_agent, ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, tokenHash, s.UserID, now.Unix(), s.ExpiresAt.Unix(), now.Unix(),
		s.UserAgent, s.IP,
	); err != nil {
		return fmt.Errorf("store: creating session: %w", err)
	}

	s.ID, s.CreatedAt, s.LastSeenAt = id, now, now
	return nil
}

// SessionByTokenHash finds a live session. Expired rows are treated as absent,
// so a stale cookie behaves exactly like no cookie at all.
func (db *DB) SessionByTokenHash(ctx context.Context, tokenHash []byte, now time.Time) (Session, error) {
	var (
		s                                Session
		createdAt, expiresAt, lastSeenAt int64
	)
	err := db.QueryRowContext(ctx, `
		SELECT id, user_id, created_at, expires_at, last_seen_at, user_agent, ip
		FROM sessions WHERE token_hash = ? AND expires_at > ?`,
		tokenHash, now.Unix(),
	).Scan(&s.ID, &s.UserID, &createdAt, &expiresAt, &lastSeenAt, &s.UserAgent, &s.IP)

	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, fmt.Errorf("store: session: %w", ErrNotFound)
	}
	if err != nil {
		return Session{}, fmt.Errorf("store: reading session: %w", err)
	}

	s.CreatedAt = time.Unix(createdAt, 0)
	s.ExpiresAt = time.Unix(expiresAt, 0)
	s.LastSeenAt = time.Unix(lastSeenAt, 0)
	return s, nil
}

// TouchSession records activity and extends the expiry, so a browser left open
// on the kitchen tablet does not get signed out mid-use.
func (db *DB) TouchSession(ctx context.Context, id string, seenAt, expiresAt time.Time) error {
	if _, err := db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?`,
		seenAt.Unix(), expiresAt.Unix(), id); err != nil {
		return fmt.Errorf("store: refreshing session %q: %w", id, err)
	}
	return nil
}

// ListSessions returns a user's live sessions, most recently seen first, so
// the interface can show where they are signed in.
func (db *DB) ListSessions(ctx context.Context, userID string, now time.Time) ([]Session, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, user_id, created_at, expires_at, last_seen_at, user_agent, ip
		FROM sessions WHERE user_id = ? AND expires_at > ?
		ORDER BY last_seen_at DESC`, userID, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("store: listing sessions: %w", err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var (
			s                                Session
			createdAt, expiresAt, lastSeenAt int64
		)
		if err := rows.Scan(&s.ID, &s.UserID, &createdAt, &expiresAt, &lastSeenAt, &s.UserAgent, &s.IP); err != nil {
			return nil, fmt.Errorf("store: scanning session: %w", err)
		}
		s.CreatedAt = time.Unix(createdAt, 0)
		s.ExpiresAt = time.Unix(expiresAt, 0)
		s.LastSeenAt = time.Unix(lastSeenAt, 0)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating sessions: %w", err)
	}
	return out, nil
}

// DeleteSession signs one browser out.
func (db *DB) DeleteSession(ctx context.Context, id string) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: deleting session %q: %w", id, err)
	}
	return nil
}

// DeleteUserSessions signs a user out everywhere, which is what a password
// change must do.
func (db *DB) DeleteUserSessions(ctx context.Context, userID string) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("store: deleting sessions of %q: %w", userID, err)
	}
	return nil
}

// PurgeExpiredSessions clears out rows nobody can use any more.
func (db *DB) PurgeExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.Unix())
	if err != nil {
		return 0, fmt.Errorf("store: purging expired sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
