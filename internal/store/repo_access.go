package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Role is what a person may do, either with a whole vault or with one secret.
type Role string

const (
	// RoleNone means no access at all. A vault someone holds no role on is
	// invisible to them, not merely read-only.
	RoleNone Role = ""

	// RoleReader may list and decrypt.
	RoleReader Role = "reader"

	// RoleWriter may also create and modify.
	RoleWriter Role = "writer"

	// RoleManager may also delete, rename, and hand out access. Only ever
	// applies to a whole vault.
	RoleManager Role = "manager"
)

// rank orders the roles so they can be compared and combined.
func (r Role) rank() int {
	switch r {
	case RoleReader:
		return 1
	case RoleWriter:
		return 2
	case RoleManager:
		return 3
	default:
		return 0
	}
}

// AtLeast reports whether r grants everything other grants.
func (r Role) AtLeast(other Role) bool { return r.rank() >= other.rank() }

// Valid reports whether r is a role that can be stored.
func (r Role) Valid() bool { return r.rank() > 0 }

// Label is the role's name in the interface.
func (r Role) Label() string {
	switch r {
	case RoleReader:
		return "lecture"
	case RoleWriter:
		return "écriture"
	case RoleManager:
		return "gestion"
	default:
		return "aucun accès"
	}
}

// Higher returns whichever of two roles grants more.
//
// Access is additive: someone who reads a whole vault and has been handed
// write access to one secret in it can write that secret. Taking the lower of
// the two would make a share able to remove a right, which nobody expects.
func Higher(a, b Role) Role {
	if a.rank() >= b.rank() {
		return a
	}
	return b
}

// Membership is one person's access to a vault or to a secret.
type Membership struct {
	UserID      string
	Username    string
	DisplayName string
	Role        Role
	GrantedAt   time.Time
	GrantedBy   string
}

// SharedSecret is a secret reachable through an individual share rather than
// through the vault that contains it.
type SharedSecret struct {
	SecretID    string
	ProjectID   string
	ProjectName string
	Env         string
	Label       string
	Name        string
	Role        Role
	UpdatedAt   time.Time
}

// SetVaultMember grants or changes someone's access to a vault.
func (db *DB) SetVaultMember(ctx context.Context, projectID, userID string, role Role, grantedBy string) error {
	if !role.Valid() {
		return fmt.Errorf("store: %q n'est pas un rôle", role)
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO vault_members (project_id, user_id, role, granted_at, granted_by)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (project_id, user_id) DO UPDATE SET
			role = excluded.role,
			granted_at = excluded.granted_at,
			granted_by = excluded.granted_by`,
		projectID, userID, string(role), time.Now().Unix(), grantedBy)
	if err != nil {
		return fmt.Errorf("store: granting access to vault %s: %w", projectID, err)
	}
	return nil
}

// RemoveVaultMember revokes someone's access to a vault.
func (db *DB) RemoveVaultMember(ctx context.Context, projectID, userID string) error {
	res, err := db.ExecContext(ctx,
		`DELETE FROM vault_members WHERE project_id = ? AND user_id = ?`, projectID, userID)
	if err != nil {
		return fmt.Errorf("store: revoking access to vault %s: %w", projectID, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: no such member: %w", ErrNotFound)
	}
	return nil
}

// VaultRole returns someone's role on a vault, RoleNone if they have none.
func (db *DB) VaultRole(ctx context.Context, projectID, userID string) (Role, error) {
	var role string
	err := db.QueryRowContext(ctx,
		`SELECT role FROM vault_members WHERE project_id = ? AND user_id = ?`,
		projectID, userID).Scan(&role)

	if errors.Is(err, sql.ErrNoRows) {
		return RoleNone, nil
	}
	if err != nil {
		return RoleNone, fmt.Errorf("store: reading vault access: %w", err)
	}
	return Role(role), nil
}

// ListVaultMembers returns everyone with access to a vault.
func (db *DB) ListVaultMembers(ctx context.Context, projectID string) ([]Membership, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT m.user_id, u.username, u.display_name, m.role, m.granted_at, m.granted_by
		FROM vault_members m
		JOIN users u ON u.id = m.user_id
		WHERE m.project_id = ?
		ORDER BY u.username COLLATE NOCASE`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: listing vault members: %w", err)
	}
	defer rows.Close()
	return scanMemberships(rows)
}

// VaultAccess is a vault together with what the person asking may do with it,
// and who it belongs to.
type VaultAccess struct {
	Project
	Role Role
	// OwnerName is the owner's account name, empty when the account is gone.
	// Carried here so a shared vault can say whose it is without a second
	// query per row.
	OwnerName string
}

// ListVaultsForUser returns the vaults someone may see, alphabetically, each
// with the role they hold on it.
//
// The role travels with the vault because the interface separates what someone
// manages from what was opened to them, and asking again per vault would mean
// one query per row.
func (db *DB) ListVaultsForUser(ctx context.Context, userID string) ([]VaultAccess, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.name, p.description, p.owner_id, p.wrapped_dek, p.created_at,
		       m.role, owner.username
		FROM projects p
		JOIN vault_members m ON m.project_id = p.id
		LEFT JOIN users owner ON owner.id = p.owner_id
		WHERE m.user_id = ?
		ORDER BY p.name COLLATE NOCASE`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: listing accessible vaults: %w", err)
	}
	defer rows.Close()

	var out []VaultAccess
	for rows.Next() {
		var (
			v         VaultAccess
			ownerID   sql.NullString
			ownerName sql.NullString
			role      string
			createdAt int64
		)
		if err := rows.Scan(&v.ID, &v.Name, &v.Description, &ownerID, &v.WrappedDEK,
			&createdAt, &role, &ownerName); err != nil {
			return nil, fmt.Errorf("store: scanning vault: %w", err)
		}
		v.OwnerID = ownerID.String
		v.OwnerName = ownerName.String
		v.CreatedAt = time.Unix(createdAt, 0)
		v.Role = Role(role)
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating vaults: %w", err)
	}
	return out, nil
}

// SoleManagerVaults returns the vaults where userID is the only manager.
//
// Deleting such an account would leave those vaults with nobody able to grant
// access to them - and since administrators no longer see what was not shared
// with them, nobody able to rescue them either. The caller is expected to
// refuse and say which vaults are in the way.
func (db *DB) SoleManagerVaults(ctx context.Context, userID string) ([]Project, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.name, p.description, p.wrapped_dek, p.created_at
		FROM projects p
		JOIN vault_members m ON m.project_id = p.id
		WHERE m.user_id = ? AND m.role = 'manager'
		  AND (
		      SELECT count(*) FROM vault_members other
		      WHERE other.project_id = p.id AND other.role = 'manager'
		  ) = 1
		ORDER BY p.name COLLATE NOCASE`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: listing solely managed vaults: %w", err)
	}
	defer rows.Close()

	var out []Project
	for rows.Next() {
		var (
			p         Project
			createdAt int64
		)
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.WrappedDEK, &createdAt); err != nil {
			return nil, fmt.Errorf("store: scanning vault: %w", err)
		}
		p.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating vaults: %w", err)
	}
	return out, nil
}

// SetSecretShare hands one secret to one person.
func (db *DB) SetSecretShare(ctx context.Context, secretID, userID string, role Role, grantedBy string) error {
	if role != RoleReader && role != RoleWriter {
		return fmt.Errorf("store: un secret ne se partage qu'en lecture ou en écriture, pas en %q", role)
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO secret_shares (secret_id, user_id, role, granted_at, granted_by)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (secret_id, user_id) DO UPDATE SET
			role = excluded.role,
			granted_at = excluded.granted_at,
			granted_by = excluded.granted_by`,
		secretID, userID, string(role), time.Now().Unix(), grantedBy)
	if err != nil {
		return fmt.Errorf("store: sharing secret %s: %w", secretID, err)
	}
	return nil
}

// RemoveSecretShare withdraws an individual share.
func (db *DB) RemoveSecretShare(ctx context.Context, secretID, userID string) error {
	res, err := db.ExecContext(ctx,
		`DELETE FROM secret_shares WHERE secret_id = ? AND user_id = ?`, secretID, userID)
	if err != nil {
		return fmt.Errorf("store: withdrawing share of secret %s: %w", secretID, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: no such share: %w", ErrNotFound)
	}
	return nil
}

// SecretShareRole returns the role someone holds on one secret through an
// individual share, ignoring whatever the vault grants them.
func (db *DB) SecretShareRole(ctx context.Context, secretID, userID string) (Role, error) {
	var role string
	err := db.QueryRowContext(ctx,
		`SELECT role FROM secret_shares WHERE secret_id = ? AND user_id = ?`,
		secretID, userID).Scan(&role)

	if errors.Is(err, sql.ErrNoRows) {
		return RoleNone, nil
	}
	if err != nil {
		return RoleNone, fmt.Errorf("store: reading secret share: %w", err)
	}
	return Role(role), nil
}

// ListSecretShares returns everyone a secret has been shared with.
func (db *DB) ListSecretShares(ctx context.Context, secretID string) ([]Membership, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT s.user_id, u.username, u.display_name, s.role, s.granted_at, s.granted_by
		FROM secret_shares s
		JOIN users u ON u.id = s.user_id
		WHERE s.secret_id = ?
		ORDER BY u.username COLLATE NOCASE`, secretID)
	if err != nil {
		return nil, fmt.Errorf("store: listing shares: %w", err)
	}
	defer rows.Close()
	return scanMemberships(rows)
}

// ListSharedSecrets returns the secrets handed to someone individually,
// excluding those they can already reach through the vault.
//
// The exclusion matters: a share on a vault you already read is noise in the
// interface, and showing the same secret in two places invites the reader to
// think they are two different things.
func (db *DB) ListSharedSecrets(ctx context.Context, userID string) ([]SharedSecret, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT sec.id, sec.project_id, p.name, sec.env, sec.name, sec.label, sh.role, sec.updated_at
		FROM secret_shares sh
		JOIN secrets sec ON sec.id = sh.secret_id
		JOIN projects p ON p.id = sec.project_id
		WHERE sh.user_id = ?
		  AND NOT EXISTS (
		      SELECT 1 FROM vault_members m
		      WHERE m.project_id = sec.project_id AND m.user_id = sh.user_id
		  )
		ORDER BY p.name COLLATE NOCASE, sec.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: listing shared secrets: %w", err)
	}
	defer rows.Close()

	var out []SharedSecret
	for rows.Next() {
		var (
			s         SharedSecret
			role      string
			updatedAt int64
		)
		if err := rows.Scan(&s.SecretID, &s.ProjectID, &s.ProjectName, &s.Env, &s.Name, &s.Label, &role, &updatedAt); err != nil {
			return nil, fmt.Errorf("store: scanning shared secret: %w", err)
		}
		s.Role = Role(role)
		s.UpdatedAt = time.Unix(updatedAt, 0)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating shared secrets: %w", err)
	}
	return out, nil
}

func scanMemberships(rows *sql.Rows) ([]Membership, error) {
	var out []Membership
	for rows.Next() {
		var (
			m         Membership
			role      string
			grantedAt int64
		)
		if err := rows.Scan(&m.UserID, &m.Username, &m.DisplayName, &role, &grantedAt, &m.GrantedBy); err != nil {
			return nil, fmt.Errorf("store: scanning membership: %w", err)
		}
		m.Role = Role(role)
		m.GrantedAt = time.Unix(grantedAt, 0)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating memberships: %w", err)
	}
	return out, nil
}
