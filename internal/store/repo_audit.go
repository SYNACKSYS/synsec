package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Actor kinds recorded in the audit log.
const (
	ActorUser   = "user"
	ActorToken  = "token"
	ActorSystem = "system"
)

// AuditEntry is one line of history.
//
// Reads are recorded as well as writes. Once an attacker holds the root key
// the encryption is worth nothing, and the only remaining question is what
// they looked at - a log of writes alone could not answer it.
type AuditEntry struct {
	ID         int64
	At         time.Time
	ActorKind  string
	ActorID    string
	ActorLabel string
	Action     string
	Target     string
	IP         string
	Detail     string
}

// AuditFilter narrows a query. Zero fields are ignored.
type AuditFilter struct {
	ActorKind string
	ActorID   string
	Action    string
	// Search matches the actor's name or the target, which is how a question
	// is usually asked: not "show me action X" but "what happened to this
	// secret", or "what did this device do".
	Search string
	Since  time.Time
	Until  time.Time
	Limit  int
}

// AppendAudit adds a line. Nothing in SYNSEC ever updates or deletes one.
func (db *DB) AppendAudit(ctx context.Context, e AuditEntry) error {
	if e.Action == "" {
		return fmt.Errorf("store: an audit entry needs an action")
	}
	if e.ActorKind == "" {
		e.ActorKind = ActorSystem
	}
	at := e.At
	if at.IsZero() {
		at = time.Now()
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO audit_log (at, actor_kind, actor_id, actor_label, action, target, ip, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		at.Unix(), e.ActorKind, e.ActorID, e.ActorLabel, e.Action, e.Target, e.IP, e.Detail,
	); err != nil {
		return fmt.Errorf("store: appending audit entry %q: %w", e.Action, err)
	}
	return nil
}

// ListAudit returns matching entries, newest first.
func (db *DB) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	query := `SELECT id, at, actor_kind, actor_id, actor_label, action, target, ip, detail
	          FROM audit_log WHERE 1 = 1`
	var args []any

	if f.ActorKind != "" {
		query += ` AND actor_kind = ?`
		args = append(args, f.ActorKind)
	}
	if f.ActorID != "" {
		query += ` AND actor_id = ?`
		args = append(args, f.ActorID)
	}
	if f.Action != "" {
		query += ` AND action = ?`
		args = append(args, f.Action)
	}
	if f.Search != "" {
		// ESCAPE, so a name holding % or _ is looked for literally instead of
		// quietly matching everything.
		pattern := "%" + escapeLike(f.Search) + "%"
		query += ` AND (actor_label LIKE ? ESCAPE '\' OR target LIKE ? ESCAPE '\')`
		args = append(args, pattern, pattern)
	}
	if !f.Since.IsZero() {
		query += ` AND at >= ?`
		args = append(args, f.Since.Unix())
	}
	if !f.Until.IsZero() {
		query += ` AND at <= ?`
		args = append(args, f.Until.Unix())
	}

	query += ` ORDER BY at DESC, id DESC`
	// An unbounded default would let the interface try to render years of
	// history in one page on a machine with very little memory.
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	query += ` LIMIT ?`
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing audit entries: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var (
			e  AuditEntry
			at int64
		)
		if err := rows.Scan(&e.ID, &at, &e.ActorKind, &e.ActorID, &e.ActorLabel,
			&e.Action, &e.Target, &e.IP, &e.Detail); err != nil {
			return nil, fmt.Errorf("store: scanning audit entry: %w", err)
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating audit entries: %w", err)
	}
	return out, nil
}

// escapeLike neutralises the wildcards in a term typed into a search box.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// AuditActions returns the distinct actions present in the log, so the
// interface can offer what actually happened rather than a hardcoded list that
// drifts as the server grows.
func (db *DB) AuditActions(ctx context.Context) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT DISTINCT action FROM audit_log ORDER BY action`)
	if err != nil {
		return nil, fmt.Errorf("store: listing audit actions: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			return nil, fmt.Errorf("store: scanning audit action: %w", err)
		}
		out = append(out, action)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating audit actions: %w", err)
	}
	return out, nil
}

// PurgeAuditBefore drops entries older than a cutoff.
//
// The only deletion SYNSEC performs on the log, and it exists because a home
// server has a finite disk, not because history is disposable. It is never
// called automatically: the owner has to ask.
func (db *DB) PurgeAuditBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM audit_log WHERE at < ?`, cutoff.Unix())
	if err != nil {
		return 0, fmt.Errorf("store: purging audit entries: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
