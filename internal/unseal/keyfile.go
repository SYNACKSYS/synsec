package unseal

import (
	"fmt"
	"os"
	"path/filepath"
)

// Keyfile is the fallback for hosts with no usable keystore: the wrapping key
// is written to a file readable only by the service account.
//
// It is deliberately the last resort. The key ends up on the same disk as the
// database it protects, so whoever takes the disk takes both - and Protection
// says exactly that, because a fallback that quietly pretends to be as good as
// a TPM is worse than no fallback at all.
type Keyfile struct {
	// Path is the file holding the raw wrapping key.
	Path string
}

func (Keyfile) Name() string { return "keyfile" }

func (Keyfile) Protection() Protection {
	return Protection{
		ResistsDiskTheft: false,
		Summary:          "Cette machine n'offre pas de coffre-fort matériel : la clé est stockée dans un fichier réservé au service.",
		Caveat:           "La clé se trouve sur le même disque que tes secrets. Quelqu'un qui repart avec le disque, ou avec une sauvegarde complète, peut tout déchiffrer. Chiffre le disque si la machine est exposée.",
	}
}

// Protect writes the key to disk and hands back the path as the handle, so the
// caller stores a location rather than key material.
//
// The write goes to a temporary file that is then renamed over the target.
// Replacing rather than refusing matters: re-sealing to this host is a normal
// step after recovering onto a new machine, and rename is atomic, so a crash
// mid-write leaves the previous key intact rather than a truncated one.
func (k Keyfile) Protect(key []byte) ([]byte, error) {
	if k.Path == "" {
		return nil, fmt.Errorf("unseal: keyfile provider needs a path")
	}
	dir := filepath.Dir(k.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("unseal: creating key directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".root.key.*")
	if err != nil {
		return nil, fmt.Errorf("unseal: creating temporary key file: %w", err)
	}
	// Removing the temporary file is a no-op once the rename has consumed it.
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("unseal: restricting key file permissions: %w", err)
	}
	if _, err := tmp.Write(key); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("unseal: writing key file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("unseal: flushing key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("unseal: closing key file: %w", err)
	}

	if err := os.Rename(tmp.Name(), k.Path); err != nil {
		return nil, fmt.Errorf("unseal: installing key file: %w", err)
	}
	return []byte(k.Path), nil
}

func (k Keyfile) Expose(handle []byte) ([]byte, error) {
	path := string(handle)
	if path == "" {
		path = k.Path
	}
	if path == "" {
		return nil, ErrNoHandle
	}

	key, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("unseal: key file %s is missing: %w", path, ErrNoHandle)
		}
		return nil, fmt.Errorf("unseal: reading key file: %w", err)
	}
	return key, nil
}
