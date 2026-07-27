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

// KeySlotRecord pairs a wrapped copy of the root key with whatever the host
// needs to reopen it.
//
// Provider and Handle are only meaningful for machine slots: they name the
// unseal provider (dpapi, systemd-tpm2, keyfile) and carry the opaque blob it
// handed back. Passphrase and recovery slots leave them empty - what opens
// those lives in a human's head or on a sheet of paper.
type KeySlotRecord struct {
	Slot      crypto.KeySlot
	Provider  string
	Handle    []byte
	CreatedAt time.Time
}

// SaveKeySlot inserts or replaces a slot.
func (db *DB) SaveKeySlot(ctx context.Context, rec KeySlotRecord) error {
	params, err := json.Marshal(rec.Slot.Params)
	if err != nil {
		return fmt.Errorf("store: encoding key slot parameters: %w", err)
	}
	createdAt := rec.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO key_slots (id, kind, salt, params, blob, provider, handle, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			kind = excluded.kind,
			salt = excluded.salt,
			params = excluded.params,
			blob = excluded.blob,
			provider = excluded.provider,
			handle = excluded.handle`,
		rec.Slot.ID, string(rec.Slot.Kind), rec.Slot.Salt, string(params),
		rec.Slot.Blob, rec.Provider, rec.Handle, createdAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("store: saving key slot %s: %w", rec.Slot.ID, err)
	}
	return nil
}

// KeySlots returns every slot, oldest first.
func (db *DB) KeySlots(ctx context.Context) ([]KeySlotRecord, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, kind, salt, params, blob, provider, handle, created_at
		FROM key_slots ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: listing key slots: %w", err)
	}
	defer rows.Close()

	var out []KeySlotRecord
	for rows.Next() {
		rec, err := scanKeySlot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating key slots: %w", err)
	}
	return out, nil
}

// KeySlotByKind returns the first slot of a given kind, which is how startup
// finds the machine slot without knowing its identifier.
func (db *DB) KeySlotByKind(ctx context.Context, kind crypto.SlotKind) (KeySlotRecord, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, kind, salt, params, blob, provider, handle, created_at
		FROM key_slots WHERE kind = ? ORDER BY created_at LIMIT 1`, string(kind))

	rec, err := scanKeySlot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return KeySlotRecord{}, fmt.Errorf("store: no %s key slot: %w", kind, ErrNotFound)
	}
	return rec, err
}

// DeleteKeySlot revokes a slot. The caller must ensure at least one slot
// survives, or the database becomes permanently unreadable.
func (db *DB) DeleteKeySlot(ctx context.Context, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM key_slots WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: deleting key slot %s: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: key slot %s: %w", id, ErrNotFound)
	}
	return nil
}

// CountKeySlots reports how many ways there are to unseal the server. The
// setup wizard refuses to finish while this is below two: a single slot means
// one lost passphrase, or one reinstalled machine, destroys every secret.
func (db *DB) CountKeySlots(ctx context.Context) (int, error) {
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM key_slots`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: counting key slots: %w", err)
	}
	return n, nil
}

// scanner covers both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanKeySlot(s scanner) (KeySlotRecord, error) {
	var (
		rec       KeySlotRecord
		kind      string
		params    sql.NullString
		provider  sql.NullString
		createdAt int64
	)
	err := s.Scan(&rec.Slot.ID, &kind, &rec.Slot.Salt, &params,
		&rec.Slot.Blob, &provider, &rec.Handle, &createdAt)
	if err != nil {
		return KeySlotRecord{}, err
	}

	rec.Slot.Kind = crypto.SlotKind(kind)
	rec.Provider = provider.String
	rec.CreatedAt = time.Unix(createdAt, 0)

	if params.Valid && params.String != "" {
		if err := json.Unmarshal([]byte(params.String), &rec.Slot.Params); err != nil {
			return KeySlotRecord{}, fmt.Errorf("store: decoding parameters of key slot %s: %w", rec.Slot.ID, err)
		}
	}
	return rec, nil
}

// SetMeta stores a singleton server setting.
func (db *DB) SetMeta(ctx context.Context, key string, value []byte) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO meta (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("store: saving meta %q: %w", key, err)
	}
	return nil
}

// Meta reads a singleton server setting.
func (db *DB) Meta(ctx context.Context, key string) ([]byte, error) {
	var value []byte
	err := db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: meta %q: %w", key, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading meta %q: %w", key, err)
	}
	return value, nil
}
