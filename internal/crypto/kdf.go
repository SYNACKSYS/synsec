package crypto

import (
	"fmt"
	"runtime"

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

// DerivationConcurrency is how many password derivations may run at once.
//
// Two per core would buy nothing: the work is memory-bound rather than
// CPU-bound. The clamp does more than schedule, though - it fixes the peak
// resident memory a burst of sign-ins can cost, which is exactly what
// HostParams weighs. That is why it lives here, beside the cost it bounds,
// rather than in the limiter that enforces it.
func DerivationConcurrency() int {
	n := runtime.NumCPU()
	if n < 2 {
		return 2
	}
	if n > 4 {
		return 4
	}
	return n
}

// HostParams returns the cost to use for passwords chosen on this machine.
//
// The two profiles above existed from the start, and nothing ever selected
// the lighter one: every machine got the 64 MiB default, including the
// Raspberry Pi and the small Synology that the manual recommends by name. A
// comment promising a behaviour the code does not have is worse than no
// comment, so the choice is made here.
//
// What decides is the peak, not the machine's label: DerivationConcurrency
// sign-ins may derive at once, so a burst costs that many working sets at the
// same time. A transient spike is allowed one eighth of physical memory -
// enough that a household server also running a home automation box is not
// pushed into swap by four people signing in together.
//
// A machine whose memory cannot be read keeps the default. Weakening password
// hashing on a host nobody has measured would be the wrong way to be wrong.
func HostParams() Argon2Params {
	total, ok := totalMemory()
	if !ok {
		return DefaultArgon2
	}
	return paramsFor(total, DerivationConcurrency())
}

// paramsFor is HostParams without the machine, so the rule can be tested on
// sizes no one here owns.
func paramsFor(totalBytes uint64, concurrent int) Argon2Params {
	peak := uint64(concurrent) * uint64(DefaultArgon2.Memory) * 1024
	if peak > totalBytes/8 {
		return LowMemoryArgon2
	}
	return DefaultArgon2
}

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
