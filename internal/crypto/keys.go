// Package crypto implements SYNSEC's envelope encryption.
//
// Three kinds of keys are involved:
//
//	root key (KEK) - never stored in the clear, only inside key slots
//	project key (DEK) - stored wrapped by the root key, one per project
//	secret values - stored sealed by their project's DEK
//
// The root key lives in memory only while the server is unsealed. Project keys
// are unwrapped for the duration of a request and zeroed immediately after.
package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// KeySize is the length in bytes of every symmetric key SYNSEC manipulates.
const KeySize = 32

// ErrKeyZeroed is returned when a key is used after having been released.
var ErrKeyZeroed = errors.New("crypto: key has been zeroed")

// Key is a symmetric key held in memory.
//
// Always release a key with Zero once the operation that needed it is over.
// Keys are reference types: copying a Key copies the pointer to the same
// backing bytes, so zeroing one zeroes them all.
type Key struct {
	b []byte
}

// NewRandomKey draws a fresh key from the system CSPRNG.
func NewRandomKey() (*Key, error) {
	b := make([]byte, KeySize)
	if err := randomBytes(b); err != nil {
		return nil, err
	}
	return &Key{b: b}, nil
}

// randomBytes fills b with cryptographically secure randomness. Any failure is
// fatal to the operation in progress: SYNSEC never falls back to a weaker
// source.
func randomBytes(b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("crypto: reading entropy: %w", err)
	}
	return nil
}

// KeyFrom adopts raw key material, typically handed over by an OS keystore
// such as DPAPI or a TPM. The caller must not reuse b afterwards: the returned
// Key takes ownership and will zero it.
func KeyFrom(b []byte) (*Key, error) {
	if len(b) != KeySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", KeySize, len(b))
	}
	return &Key{b: b}, nil
}

// Bytes exposes the raw key material. It stays valid until Zero is called.
func (k *Key) Bytes() []byte { return k.b }

// Zeroed reports whether the key has already been released.
func (k *Key) Zeroed() bool { return k == nil || k.b == nil }

// Zero overwrites the key material and marks the key unusable. It is safe to
// call more than once, which makes it suitable for a deferred call.
func (k *Key) Zero() {
	if k == nil || k.b == nil {
		return
	}
	for i := range k.b {
		k.b[i] = 0
	}
	k.b = nil
}
