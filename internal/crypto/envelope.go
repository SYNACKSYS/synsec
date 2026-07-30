package crypto

import "fmt"

// SecretRef identifies where a secret value lives. Every field takes part in
// the authenticated data, so a sealed value is cryptographically pinned to its
// project, its environment, its name and its version.
//
// Concretely: an attacker who can write to the database cannot copy the
// ciphertext of the test MQTT password over the production one, nor roll a
// secret back to an older version by swapping blobs. The tag will not verify.
//
// It also means a secret cannot be renamed in place: the name is part of what
// the tag covers, so changing it requires decrypting and resealing every
// version.
type SecretRef struct {
	ProjectID string
	Env       string
	Name      string
	Version   int64
}

func (r SecretRef) aad() []byte {
	return bindAAD("synsec/secret/v1",
		r.ProjectID,
		r.Env,
		r.Name,
		fmt.Sprintf("%d", r.Version),
	)
}

// SealSecret encrypts a secret value under its project key.
func SealSecret(dek *Key, ref SecretRef, plaintext []byte) ([]byte, error) {
	if err := ref.validate(); err != nil {
		return nil, err
	}
	return seal(dek, ref.aad(), plaintext)
}

// OpenSecret decrypts a secret value. It fails if ref does not describe
// exactly the location the value was sealed for.
func OpenSecret(dek *Key, ref SecretRef, blob []byte) ([]byte, error) {
	if err := ref.validate(); err != nil {
		return nil, err
	}
	return open(dek, ref.aad(), blob)
}

func (r SecretRef) validate() error {
	switch {
	case r.ProjectID == "":
		return fmt.Errorf("crypto: secret reference needs a project")
	case r.Name == "":
		return fmt.Errorf("crypto: secret reference needs a name")
	case r.Version < 1:
		return fmt.Errorf("crypto: secret version must be positive, got %d", r.Version)
	}
	return nil
}

// WrapDEK seals a project key under the root key for storage.
//
// One key per project, rather than one per secret, is a deliberate middle
// ground: rotating a project's key touches only that project, the root key can
// be rotated by rewrapping a handful of blobs, and a decryption key is only
// ever resident for the project a request actually touches.
func WrapDEK(root *Key, projectID string, dek *Key) ([]byte, error) {
	if projectID == "" {
		return nil, fmt.Errorf("crypto: cannot wrap a project key without a project")
	}
	return seal(root, bindAAD("synsec/dek/v1", projectID), dek.Bytes())
}

// UnwrapDEK recovers a project key. The caller owns the result and must Zero
// it once the request is served.
func UnwrapDEK(root *Key, projectID string, blob []byte) (*Key, error) {
	raw, err := open(root, bindAAD("synsec/dek/v1", projectID), blob)
	if err != nil {
		return nil, err
	}
	return KeyFrom(raw)
}

// SealSetting encrypts a piece of configuration that is itself a credential -
// the address of a webhook, the key used to sign what is sent to it.
//
// Directly under the root key, with no key of its own: there is one of each of
// these, they are read at start-up and when somebody edits them, and a per
// setting key would be one more thing to rotate for no gain.
//
// The name is bound into the AAD, so a value copied from one setting to
// another fails to open instead of being read as something it never was.
func SealSetting(root *Key, domain, name string, plaintext []byte) ([]byte, error) {
	if domain == "" || name == "" {
		return nil, fmt.Errorf("crypto: a sealed setting needs a domain and a name")
	}
	return seal(root, bindAAD("synsec/setting/v1", domain, name), plaintext)
}

// OpenSealedSetting recovers one.
func OpenSealedSetting(root *Key, domain, name string, blob []byte) ([]byte, error) {
	if domain == "" || name == "" {
		return nil, fmt.Errorf("crypto: a sealed setting needs a domain and a name")
	}
	return open(root, bindAAD("synsec/setting/v1", domain, name), blob)
}
