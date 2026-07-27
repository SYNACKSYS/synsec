package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// MaxSecretNameLength bounds a name.
const MaxSecretNameLength = 128

// secretNameRule is what a name may contain.
//
// Letters, digits, dashes and underscores, and nothing else: the name is meant
// to be usable as written in a script, a configuration file or an environment
// variable, without anyone having to work out an escaping rule. Spaces and
// slashes are refused rather than silently transformed, so what you typed is
// what is stored.
var secretNameRule = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ValidSecretName reports whether a name may be written.
func ValidSecretName(name string) error {
	switch {
	case name == "":
		return errors.New("store: un secret a besoin d'un nom")
	case len(name) > MaxSecretNameLength:
		return fmt.Errorf("store: le nom dépasse %d caractères", MaxSecretNameLength)
	case !secretNameRule.MatchString(name):
		return errors.New("store: le nom ne peut contenir que des lettres, des chiffres, des tirets et des soulignés")
	}
	return nil
}

// SecretLocation addresses one secret inside a vault.
type SecretLocation struct {
	ProjectID string
	Env       string
	Name      string
}

// Secret is a secret's metadata. It never carries the value, so listing a
// vault costs nothing in cryptography and leaks nothing if the response is
// logged.
type Secret struct {
	ID string
	SecretLocation
	CurrentVersion int64
	// Label is what its owner wrote; Name is the slug that addresses it.
	Label          string
	Comment        string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// VersionInfo describes one entry in a secret's history.
type VersionInfo struct {
	Version   int64
	CreatedAt time.Time
	CreatedBy string
}

// SealFunc encrypts a value for a specific version number.
//
// Sealing is a callback rather than a parameter because the version number is
// part of the authenticated data: the ciphertext cannot be produced until the
// version is known, and the version is not known until the transaction has
// looked at the current state. Doing it any other way would mean either
// guessing the version or leaving a window where two concurrent writes seal
// against the same one.
type SealFunc func(version int64) (blob []byte, err error)

// PutSecret writes a new version of a secret, creating it if it does not exist
// yet, and returns the resulting metadata.
//
// label is applied only when the secret is created. Renaming what people read
// is SetSecretLabel's job, and letting a write silently change it would mean a
// device pushing a value could rename someone else's entry.
func (db *DB) PutSecret(ctx context.Context, loc SecretLocation, label, author string, seal SealFunc) (Secret, error) {
	if err := loc.validate(); err != nil {
		return Secret{}, err
	}
	if err := ValidSecretName(loc.Name); err != nil {
		return Secret{}, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Secret{}, fmt.Errorf("store: starting secret write: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	var (
		id        string
		version   int64
		createdAt int64
		comment   string
		stored    string
	)
	err = tx.QueryRowContext(ctx,
		`SELECT id, current_version, created_at, comment, label FROM secrets
		 WHERE project_id = ? AND env = ? AND name = ?`,
		loc.ProjectID, loc.Env, loc.Name,
	).Scan(&id, &version, &createdAt, &comment, &stored)

	now := time.Now()
	isNew := errors.Is(err, sql.ErrNoRows)
	switch {
	case isNew:
		if id, err = NewID(); err != nil {
			return Secret{}, err
		}
		version, createdAt = 0, now.Unix()
	case err != nil:
		return Secret{}, fmt.Errorf("store: reading secret %s: %w", loc.Name, err)
	}
	version++

	blob, err := seal(version)
	if err != nil {
		return Secret{}, fmt.Errorf("store: sealing secret %s: %w", loc.Name, err)
	}
	if len(blob) == 0 {
		return Secret{}, fmt.Errorf("store: refusing to store an empty ciphertext for %s", loc.Name)
	}

	if isNew {
		// An empty label is allowed: a device pushing a value has no opinion
		// on what to call it, and the interface then shows the slug.
		stored = strings.TrimSpace(label)
		_, err = tx.ExecContext(ctx,
			`INSERT INTO secrets (id, project_id, env, name, current_version, comment, label, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, '', ?, ?, ?)`,
			id, loc.ProjectID, loc.Env, loc.Name, version, stored, createdAt, now.Unix())
	} else {
		_, err = tx.ExecContext(ctx,
			`UPDATE secrets SET current_version = ?, updated_at = ? WHERE id = ?`,
			version, now.Unix(), id)
	}
	if err != nil {
		return Secret{}, fmt.Errorf("store: writing secret %s: %w", loc.Name, err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO secret_versions (secret_id, version, blob, created_at, created_by)
		 VALUES (?, ?, ?, ?, ?)`,
		id, version, blob, now.Unix(), author,
	); err != nil {
		return Secret{}, fmt.Errorf("store: writing version %d of %s: %w", version, loc.Name, err)
	}

	if err := tx.Commit(); err != nil {
		return Secret{}, fmt.Errorf("store: committing secret %s: %w", loc.Name, err)
	}

	return Secret{
		ID:             id,
		SecretLocation: loc,
		CurrentVersion: version,
		Label:          stored,
		Comment:        comment,
		CreatedAt:      time.Unix(createdAt, 0),
		UpdatedAt:      now,
	}, nil
}

// SetSecretLabel renames what people read.
//
// Free to change at any time, unlike the slug: the label takes no part in the
// encryption, so nothing has to be decrypted and no device that addresses the
// secret by its slug notices.
func (db *DB) SetSecretLabel(ctx context.Context, loc SecretLocation, label string) error {
	res, err := db.ExecContext(ctx,
		`UPDATE secrets SET label = ? WHERE project_id = ? AND env = ? AND name = ?`,
		strings.TrimSpace(label), loc.ProjectID, loc.Env, loc.Name)
	if err != nil {
		return fmt.Errorf("store: renaming %s: %w", loc.Name, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: secret %s: %w", loc.Name, ErrNotFound)
	}
	return nil
}

// Display is what the interface shows: the label if there is one, the slug
// otherwise. A secret created by a device has no label and is better shown as
// mqtt_password than as a blank line.
func (s Secret) Display() string {
	if s.Label != "" {
		return s.Label
	}
	return s.Name
}

// SecretMeta fetches a secret's metadata without its value.
//
// Access checks need the identifier before they can decide whether the caller
// may see the value, so this deliberately touches no ciphertext.
func (db *DB) SecretMeta(ctx context.Context, loc SecretLocation) (Secret, error) {
	if err := loc.validate(); err != nil {
		return Secret{}, err
	}

	var (
		s                    Secret
		createdAt, updatedAt int64
	)
	err := db.QueryRowContext(ctx, `
		SELECT id, current_version, comment, label, created_at, updated_at
		FROM secrets WHERE project_id = ? AND env = ? AND name = ?`,
		loc.ProjectID, loc.Env, loc.Name,
	).Scan(&s.ID, &s.CurrentVersion, &s.Comment, &s.Label, &createdAt, &updatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, fmt.Errorf("store: secret %s: %w", loc.Name, ErrNotFound)
	}
	if err != nil {
		return Secret{}, fmt.Errorf("store: reading secret %s: %w", loc.Name, err)
	}

	s.SecretLocation = loc
	s.CreatedAt, s.UpdatedAt = time.Unix(createdAt, 0), time.Unix(updatedAt, 0)
	return s, nil
}

// Secret fetches one secret and the sealed bytes of its current version.
func (db *DB) Secret(ctx context.Context, loc SecretLocation) (Secret, []byte, error) {
	if err := loc.validate(); err != nil {
		return Secret{}, nil, err
	}

	var (
		s                    Secret
		blob                 []byte
		createdAt, updatedAt int64
	)
	err := db.QueryRowContext(ctx, `
		SELECT s.id, s.current_version, s.comment, s.label, s.created_at, s.updated_at, v.blob
		FROM secrets s
		JOIN secret_versions v ON v.secret_id = s.id AND v.version = s.current_version
		WHERE s.project_id = ? AND s.env = ? AND s.name = ?`,
		loc.ProjectID, loc.Env, loc.Name,
	).Scan(&s.ID, &s.CurrentVersion, &s.Comment, &s.Label, &createdAt, &updatedAt, &blob)

	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, nil, fmt.Errorf("store: secret %s: %w", loc.Name, ErrNotFound)
	}
	if err != nil {
		return Secret{}, nil, fmt.Errorf("store: reading secret %s: %w", loc.Name, err)
	}

	s.SecretLocation = loc
	s.CreatedAt, s.UpdatedAt = time.Unix(createdAt, 0), time.Unix(updatedAt, 0)
	return s, blob, nil
}

// SecretVersionBlob fetches the sealed bytes of one historical version, so the
// caller can decrypt it and write it back as a new version.
//
// Rolling back is a new version rather than a pointer moved backwards: the
// version number is authenticated, so an old ciphertext simply will not open
// under a new one. The audit trail keeps the full history either way.
func (db *DB) SecretVersionBlob(ctx context.Context, secretID string, version int64) ([]byte, error) {
	var blob []byte
	err := db.QueryRowContext(ctx,
		`SELECT blob FROM secret_versions WHERE secret_id = ? AND version = ?`,
		secretID, version,
	).Scan(&blob)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: version %d of secret %s: %w", version, secretID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading version %d: %w", version, err)
	}
	return blob, nil
}

// ListVersions returns a secret's history, newest first.
func (db *DB) ListVersions(ctx context.Context, secretID string) ([]VersionInfo, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT version, created_at, created_by FROM secret_versions
		 WHERE secret_id = ? ORDER BY version DESC`, secretID)
	if err != nil {
		return nil, fmt.Errorf("store: listing versions: %w", err)
	}
	defer rows.Close()

	var out []VersionInfo
	for rows.Next() {
		var (
			v         VersionInfo
			createdAt int64
		)
		if err := rows.Scan(&v.Version, &createdAt, &v.CreatedBy); err != nil {
			return nil, fmt.Errorf("store: scanning version: %w", err)
		}
		v.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating versions: %w", err)
	}
	return out, nil
}

// ListSecrets returns the metadata of every secret in a vault, alphabetically,
// without touching a single ciphertext.
//
// There is no prefix and no filter: a secret is one entry, and a vault is the
// only grouping there is.
func (db *DB) ListSecrets(ctx context.Context, projectID, env string) ([]Secret, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, name, current_version, comment, label, created_at, updated_at
		FROM secrets
		WHERE project_id = ? AND env = ?
		ORDER BY name COLLATE NOCASE`, projectID, env)
	if err != nil {
		return nil, fmt.Errorf("store: listing secrets: %w", err)
	}
	defer rows.Close()

	var out []Secret
	for rows.Next() {
		s := Secret{SecretLocation: SecretLocation{ProjectID: projectID, Env: env}}
		var createdAt, updatedAt int64
		if err := rows.Scan(&s.ID, &s.Name, &s.CurrentVersion, &s.Comment, &s.Label, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("store: scanning secret: %w", err)
		}
		s.CreatedAt, s.UpdatedAt = time.Unix(createdAt, 0), time.Unix(updatedAt, 0)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating secrets: %w", err)
	}
	return out, nil
}

// SetSecretComment updates the human note attached to a secret. The note is
// not encrypted, so the interface warns against putting anything sensitive in
// it.
func (db *DB) SetSecretComment(ctx context.Context, loc SecretLocation, comment string) error {
	res, err := db.ExecContext(ctx,
		`UPDATE secrets SET comment = ? WHERE project_id = ? AND env = ? AND name = ?`,
		comment, loc.ProjectID, loc.Env, loc.Name)
	if err != nil {
		return fmt.Errorf("store: updating comment of %s: %w", loc.Name, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: secret %s: %w", loc.Name, ErrNotFound)
	}
	return nil
}

// DeleteSecret removes a secret and its whole history.
func (db *DB) DeleteSecret(ctx context.Context, loc SecretLocation) error {
	res, err := db.ExecContext(ctx,
		`DELETE FROM secrets WHERE project_id = ? AND env = ? AND name = ?`,
		loc.ProjectID, loc.Env, loc.Name)
	if err != nil {
		return fmt.Errorf("store: deleting secret %s: %w", loc.Name, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: secret %s: %w", loc.Name, ErrNotFound)
	}
	return nil
}

// ResealFunc re-encrypts one stored ciphertext under a new vault key.
type ResealFunc func(env, name string, version int64, blob []byte) ([]byte, error)

// RotateVaultBlobs re-encrypts every version of every secret in a vault and
// swaps in the new wrapped key, all inside one transaction.
//
// The atomicity is the entire point. A rotation that stopped halfway would
// leave some versions under the new key while the vault still advertised the
// old one, and every one of those values would be unreadable forever - the
// exact failure a secret server exists to prevent.
func (db *DB) RotateVaultBlobs(ctx context.Context, projectID string, reseal ResealFunc, wrappedDEK []byte) error {
	if len(wrappedDEK) == 0 {
		return fmt.Errorf("store: rotation needs the new wrapped key")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: starting rotation: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	type versionRow struct {
		secretID string
		env      string
		name     string
		version  int64
		blob     []byte
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT v.secret_id, s.env, s.name, v.version, v.blob
		FROM secret_versions v
		JOIN secrets s ON s.id = v.secret_id
		WHERE s.project_id = ?`, projectID)
	if err != nil {
		return fmt.Errorf("store: reading vault %s for rotation: %w", projectID, err)
	}

	// Collected before updating: a cursor cannot be walked while the rows it
	// is sitting on are being rewritten.
	var pending []versionRow
	for rows.Next() {
		var r versionRow
		if err := rows.Scan(&r.secretID, &r.env, &r.name, &r.version, &r.blob); err != nil {
			rows.Close()
			return fmt.Errorf("store: scanning version during rotation: %w", err)
		}
		pending = append(pending, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("store: iterating versions during rotation: %w", err)
	}
	rows.Close()

	for _, r := range pending {
		fresh, err := reseal(r.env, r.name, r.version, r.blob)
		if err != nil {
			return fmt.Errorf("store: resealing version %d of %s: %w", r.version, r.name, err)
		}
		if len(fresh) == 0 {
			return fmt.Errorf("store: resealing version %d of %s produced nothing", r.version, r.name)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE secret_versions SET blob = ? WHERE secret_id = ? AND version = ?`,
			fresh, r.secretID, r.version,
		); err != nil {
			return fmt.Errorf("store: writing resealed version %d of %s: %w", r.version, r.name, err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE projects SET wrapped_dek = ? WHERE id = ?`, wrappedDEK, projectID,
	); err != nil {
		return fmt.Errorf("store: swapping wrapped key of vault %s: %w", projectID, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: committing rotation of vault %s: %w", projectID, err)
	}
	return nil
}

func (loc SecretLocation) validate() error {
	switch {
	case loc.ProjectID == "":
		return fmt.Errorf("store: secret location needs a vault")
	case loc.Env == "":
		return fmt.Errorf("store: secret location needs an environment")
	case loc.Name == "":
		return fmt.Errorf("store: secret location needs a name")
	}
	return nil
}
