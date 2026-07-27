package crypto

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

// SaltSize is the length of the per-slot salt fed to Argon2id.
const SaltSize = 16

// Argon2Params configures the password hashing cost. They are stored alongside
// every slot so that raising the cost later does not lock existing users out:
// each slot is verified with the parameters it was created with.
type Argon2Params struct {
	// Memory is the working set in KiB.
	Memory uint32 `json:"memory"`
	// Time is the number of passes over that memory.
	Time uint32 `json:"time"`
	// Threads is the degree of parallelism.
	Threads uint8 `json:"threads"`
}

// DefaultArgon2 targets roughly a quarter of a second on a modern desktop CPU.
//
// The 64 MiB working set is transient - it is only allocated while a human is
// logging in, never on the machine-token path, which is where SYNSEC's request
// volume actually lives. That asymmetry is deliberate: see AuthenticateToken.
var DefaultArgon2 = Argon2Params{Memory: 64 * 1024, Time: 3, Threads: 4}

// LowMemoryArgon2 suits small single-board computers where a 64 MiB spike
// during login would be felt.
var LowMemoryArgon2 = Argon2Params{Memory: 16 * 1024, Time: 4, Threads: 2}

func (p Argon2Params) valid() error {
	switch {
	case p.Memory < 8*1024:
		return fmt.Errorf("crypto: argon2 memory too low (%d KiB)", p.Memory)
	case p.Time < 1:
		return fmt.Errorf("crypto: argon2 time must be at least 1")
	case p.Threads < 1:
		return fmt.Errorf("crypto: argon2 threads must be at least 1")
	}
	return nil
}

// Derive stretches a human secret into KeySize bytes.
//
// Exported for password verification, which needs the raw digest rather than a
// Key: a stored password hash is compared, never used to decrypt anything.
func (p Argon2Params) Derive(secret, salt []byte) ([]byte, error) {
	if err := p.valid(); err != nil {
		return nil, err
	}
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("crypto: salt must be %d bytes, got %d", SaltSize, len(salt))
	}
	return argon2.IDKey(secret, salt, p.Time, p.Memory, p.Threads, KeySize), nil
}

// derive turns a human secret into a wrapping key.
func (p Argon2Params) derive(secret, salt []byte) (*Key, error) {
	b, err := p.Derive(secret, salt)
	if err != nil {
		return nil, err
	}
	return &Key{b: b}, nil
}

// NewSalt draws a fresh random salt.
func NewSalt() ([]byte, error) {
	s := make([]byte, SaltSize)
	if err := randomBytes(s); err != nil {
		return nil, err
	}
	return s, nil
}
