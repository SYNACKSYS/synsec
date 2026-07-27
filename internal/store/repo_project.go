package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// DefaultEnvironment is the single environment created with every vault.
//
// The data model supports as many as you like, but the interface only reveals
// them behind an advanced toggle: a household running Home Assistant has one,
// and asking its owner to choose between "dev" and "prod" before storing a
// Wi-Fi password would be a bad first impression.
const DefaultEnvironment = "prod"

// Project is a vault: a named container with its own encryption key.
type Project struct {
	ID          string
	Name        string
	Description string
	// OwnerID is who created the vault. Empty when the account has since been
	// removed; the vault survives its owner.
	OwnerID    string
	WrappedDEK []byte
	CreatedAt  time.Time
}

// Environment partitions a vault. Most installations only ever see the default
// one.
type Environment struct {
	ID        string
	ProjectID string
	Slug      string
	Name      string
	Position  int
}

// CreateProject stores a new vault along with its default environment, and
// fills in ID and CreatedAt.
//
// Both rows are written in one transaction: a vault without an environment
// would accept no secrets, and half-created vaults are exactly the sort of
// state a non-technical owner has no way to diagnose or repair.
func (db *DB) CreateProject(ctx context.Context, p *Project) error {
	if p.Name == "" {
		return fmt.Errorf("store: a vault needs a name")
	}
	if len(p.WrappedDEK) == 0 {
		return fmt.Errorf("store: a vault needs a wrapped encryption key")
	}

	// The caller may set ID beforehand. It has to be allowed to: a vault's
	// identifier is part of the authenticated data binding its encryption key,
	// so the key cannot be wrapped until the identifier is settled.
	id := p.ID
	if id == "" {
		var err error
		if id, err = NewID(); err != nil {
			return err
		}
	}

	envID, err := NewID()
	if err != nil {
		return err
	}
	created := time.Now()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: starting vault creation: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO projects (id, name, description, owner_id, wrapped_dek, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, p.Name, p.Description, nullableString(p.OwnerID), p.WrappedDEK, created.Unix(),
	); err != nil {
		return fmt.Errorf("store: creating vault %q: %w", p.Name, err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO environments (id, project_id, slug, name, position) VALUES (?, ?, ?, ?, 0)`,
		envID, id, DefaultEnvironment, "Production",
	); err != nil {
		return fmt.Errorf("store: creating default environment for %q: %w", p.Name, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: committing vault %q: %w", p.Name, err)
	}

	p.ID, p.CreatedAt = id, created
	return nil
}

// Project looks a vault up by identifier.
func (db *DB) Project(ctx context.Context, id string) (Project, error) {
	return db.scanProject(db.QueryRowContext(ctx,
		`SELECT id, name, description, owner_id, wrapped_dek, created_at FROM projects WHERE id = ?`, id), id)
}

// ProjectByName looks a vault up by name, case-insensitively.
func (db *DB) ProjectByName(ctx context.Context, name string) (Project, error) {
	return db.scanProject(db.QueryRowContext(ctx,
		`SELECT id, name, description, owner_id, wrapped_dek, created_at FROM projects WHERE name = ? COLLATE NOCASE`, name), name)
}

func (db *DB) scanProject(row *sql.Row, what string) (Project, error) {
	var (
		p         Project
		createdAt int64
	)
	var owner sql.NullString
	err := row.Scan(&p.ID, &p.Name, &p.Description, &owner, &p.WrappedDEK, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, fmt.Errorf("store: vault %q: %w", what, ErrNotFound)
	}
	if err != nil {
		return Project{}, fmt.Errorf("store: reading vault %q: %w", what, err)
	}
	p.OwnerID = owner.String
	p.CreatedAt = time.Unix(createdAt, 0)
	return p, nil
}

// ListProjects returns every vault, alphabetically.
func (db *DB) ListProjects(ctx context.Context) ([]Project, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, description, owner_id, wrapped_dek, created_at FROM projects ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("store: listing vaults: %w", err)
	}
	defer rows.Close()

	var out []Project
	for rows.Next() {
		var (
			p         Project
			createdAt int64
		)
		var owner sql.NullString
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &owner, &p.WrappedDEK, &createdAt); err != nil {
			return nil, fmt.Errorf("store: scanning vault: %w", err)
		}
		p.OwnerID = owner.String
		p.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating vaults: %w", err)
	}
	return out, nil
}

// RenameProject changes a vault's display name and description.
func (db *DB) RenameProject(ctx context.Context, id, name, description string) error {
	if name == "" {
		return fmt.Errorf("store: a vault needs a name")
	}
	res, err := db.ExecContext(ctx,
		`UPDATE projects SET name = ?, description = ? WHERE id = ?`, name, description, id)
	if err != nil {
		return fmt.Errorf("store: renaming vault %s: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: vault %s: %w", id, ErrNotFound)
	}
	return nil
}

// DeleteProject removes a vault and, by cascade, its environments, secrets,
// every version of them and the tokens scoped to it.
//
// The audit log deliberately does not cascade: the record that a vault once
// existed and was deleted must outlive the vault.
func (db *DB) DeleteProject(ctx context.Context, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: deleting vault %s: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: vault %s: %w", id, ErrNotFound)
	}
	return nil
}

// UpdateWrappedDEK replaces a vault's wrapped encryption key, used when the
// root key is rotated.
func (db *DB) UpdateWrappedDEK(ctx context.Context, id string, wrapped []byte) error {
	if len(wrapped) == 0 {
		return fmt.Errorf("store: refusing to store an empty wrapped key for vault %s", id)
	}
	res, err := db.ExecContext(ctx, `UPDATE projects SET wrapped_dek = ? WHERE id = ?`, wrapped, id)
	if err != nil {
		return fmt.Errorf("store: updating wrapped key of vault %s: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: vault %s: %w", id, ErrNotFound)
	}
	return nil
}

// CreateEnvironment adds an environment to a vault.
func (db *DB) CreateEnvironment(ctx context.Context, e *Environment) error {
	if e.Slug == "" || e.ProjectID == "" {
		return fmt.Errorf("store: an environment needs a vault and a slug")
	}
	id, err := NewID()
	if err != nil {
		return err
	}
	name := e.Name
	if name == "" {
		name = e.Slug
	}

	if _, err := db.ExecContext(ctx,
		`INSERT INTO environments (id, project_id, slug, name, position) VALUES (?, ?, ?, ?, ?)`,
		id, e.ProjectID, e.Slug, name, e.Position,
	); err != nil {
		return fmt.Errorf("store: creating environment %q: %w", e.Slug, err)
	}
	e.ID, e.Name = id, name
	return nil
}

// ListEnvironments returns a vault's environments in display order.
func (db *DB) ListEnvironments(ctx context.Context, projectID string) ([]Environment, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, project_id, slug, name, position FROM environments
		 WHERE project_id = ? ORDER BY position, slug`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: listing environments: %w", err)
	}
	defer rows.Close()

	var out []Environment
	for rows.Next() {
		var e Environment
		if err := rows.Scan(&e.ID, &e.ProjectID, &e.Slug, &e.Name, &e.Position); err != nil {
			return nil, fmt.Errorf("store: scanning environment: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating environments: %w", err)
	}
	return out, nil
}

// nullableString stores an empty identifier as NULL, so a foreign key on it
// means "nobody" rather than "a user whose id is the empty string".
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
