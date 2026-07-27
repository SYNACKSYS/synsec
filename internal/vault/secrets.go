package vault

import (
	"context"
	"fmt"

	"synsec/internal/crypto"
	"synsec/internal/store"
)

// CreateVault makes a new vault with its own encryption key.
func (m *Manager) CreateVault(ctx context.Context, name, description, ownerID string) (store.Project, error) {
	// The identifier is settled first: it is authenticated into the wrapping
	// of the vault's key, so it cannot be assigned by the insert.
	id, err := store.NewID()
	if err != nil {
		return store.Project{}, err
	}

	p := store.Project{ID: id, Name: name, Description: description, OwnerID: ownerID}
	err = m.withRoot(func(root *crypto.Key) error {
		dek, err := crypto.NewRandomKey()
		if err != nil {
			return err
		}
		defer dek.Zero()

		wrapped, err := crypto.WrapDEK(root, id, dek)
		if err != nil {
			return fmt.Errorf("vault: wrapping key of vault %q: %w", name, err)
		}
		p.WrappedDEK = wrapped
		return m.db.CreateProject(ctx, &p)
	})
	if err != nil {
		return store.Project{}, err
	}
	return p, nil
}

// GetSecret returns the decrypted current value of one secret.
func (m *Manager) GetSecret(ctx context.Context, loc store.SecretLocation) ([]byte, error) {
	var value []byte
	err := m.withDEK(ctx, loc.ProjectID, func(dek *crypto.Key) error {
		secret, blob, err := m.db.Secret(ctx, loc)
		if err != nil {
			return err
		}
		value, err = crypto.OpenSecret(dek, secretRef(loc, secret.CurrentVersion), blob)
		if err != nil {
			return fmt.Errorf("vault: decrypting %s: %w", loc.Name, err)
		}
		return nil
	})
	return value, err
}

// PutSecret stores a new version of a secret, creating it if needed.
func (m *Manager) PutSecret(ctx context.Context, loc store.SecretLocation, value []byte, label, author string) (store.Secret, error) {
	var out store.Secret
	err := m.withDEK(ctx, loc.ProjectID, func(dek *crypto.Key) error {
		s, err := m.db.PutSecret(ctx, loc, label, author, func(version int64) ([]byte, error) {
			return crypto.SealSecret(dek, secretRef(loc, version), value)
		})
		out = s
		return err
	})
	return out, err
}

// RevertSecret restores an earlier value by writing it back as a new version.
//
// It cannot be done by moving a pointer: the version number is authenticated,
// so an old ciphertext will not open under a new version. Decrypting and
// resealing is the only honest way, and it has the merit of leaving the
// history intact instead of rewriting it.
func (m *Manager) RevertSecret(ctx context.Context, loc store.SecretLocation, toVersion int64, author string) (store.Secret, error) {
	var out store.Secret
	err := m.withDEK(ctx, loc.ProjectID, func(dek *crypto.Key) error {
		current, err := m.db.SecretMeta(ctx, loc)
		if err != nil {
			return err
		}
		if toVersion < 1 || toVersion > current.CurrentVersion {
			return fmt.Errorf("vault: %s n'a pas de version %d", loc.Name, toVersion)
		}

		blob, err := m.db.SecretVersionBlob(ctx, current.ID, toVersion)
		if err != nil {
			return err
		}
		old, err := crypto.OpenSecret(dek, secretRef(loc, toVersion), blob)
		if err != nil {
			return fmt.Errorf("vault: decrypting version %d of %s: %w", toVersion, loc.Name, err)
		}

		out, err = m.db.PutSecret(ctx, loc, "", author, func(version int64) ([]byte, error) {
			return crypto.SealSecret(dek, secretRef(loc, version), old)
		})
		return err
	})
	return out, err
}

// RotateVaultKey draws a new encryption key for a vault and re-encrypts every
// secret under it, used when a key is believed compromised.
//
// Every version is re-encrypted, not just the current one, because history
// that stays readable under the old key is not really rotated.
func (m *Manager) RotateVaultKey(ctx context.Context, projectID string) error {
	return m.withRoot(func(root *crypto.Key) error {
		p, err := m.db.Project(ctx, projectID)
		if err != nil {
			return err
		}
		old, err := crypto.UnwrapDEK(root, projectID, p.WrappedDEK)
		if err != nil {
			return fmt.Errorf("vault: opening vault %s: %w", projectID, err)
		}
		defer old.Zero()

		fresh, err := crypto.NewRandomKey()
		if err != nil {
			return err
		}
		defer fresh.Zero()

		wrapped, err := crypto.WrapDEK(root, projectID, fresh)
		if err != nil {
			return err
		}

		return m.db.RotateVaultBlobs(ctx, projectID,
			func(env, name string, version int64, blob []byte) ([]byte, error) {
				loc := store.SecretLocation{ProjectID: projectID, Env: env, Name: name}
				plain, err := crypto.OpenSecret(old, secretRef(loc, version), blob)
				if err != nil {
					return nil, fmt.Errorf("vault: decrypting version %d of %s: %w", version, name, err)
				}
				return crypto.SealSecret(fresh, secretRef(loc, version), plain)
			}, wrapped)
	})
}

// withDEK unwraps a vault's key for the duration of one operation and zeroes
// it immediately after.
//
// The key is deliberately not cached: unwrapping costs a few microseconds,
// while a cache would keep decryption keys resident for every vault the server
// has ever touched.
func (m *Manager) withDEK(ctx context.Context, projectID string, fn func(dek *crypto.Key) error) error {
	return m.withRoot(func(root *crypto.Key) error {
		p, err := m.db.Project(ctx, projectID)
		if err != nil {
			return err
		}
		dek, err := crypto.UnwrapDEK(root, projectID, p.WrappedDEK)
		if err != nil {
			return fmt.Errorf("vault: opening vault %s: %w", projectID, err)
		}
		defer dek.Zero()
		return fn(dek)
	})
}

func secretRef(loc store.SecretLocation, version int64) crypto.SecretRef {
	return crypto.SecretRef{
		ProjectID: loc.ProjectID,
		Env:       loc.Env,
		Name:      loc.Name,
		Version:   version,
	}
}
