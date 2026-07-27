package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"strings"
)

// A service token reads syn_<id>_<secret>.
//
// The identifier travels in clear so the server can look the row up directly
// instead of hashing its way through every token on the server. The secret is
// 256 bits of CSPRNG output.
const (
	tokenPrefix      = "syn"
	tokenSecretBytes = 32
)

// tokenEncoding matches the one used for row identifiers: lowercase base32,
// no padding, so a token survives being pasted into a YAML file, a URL or a
// shell script without quoting surprises.
var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrMalformedToken means the string is not shaped like a service token. It is
// returned before any database lookup.
var ErrMalformedToken = errors.New("auth: malformed service token")

// NewServiceToken mints a token, returning the string to show the owner once,
// the identifier to store, and the hash to verify against later.
//
// The plaintext is never stored anywhere: if it is lost, the token is replaced,
// not recovered.
func NewServiceToken(id string) (plaintext string, secretHash []byte, err error) {
	if id == "" {
		return "", nil, errors.New("auth: a service token needs an identifier")
	}

	raw := make([]byte, tokenSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	secret := strings.ToLower(tokenEncoding.EncodeToString(raw))

	return tokenPrefix + "_" + id + "_" + secret, HashTokenSecret(secret), nil
}

// ParseServiceToken splits a token into its identifier and secret halves
// without touching the database.
func ParseServiceToken(s string) (id, secret string, err error) {
	parts := strings.Split(strings.TrimSpace(s), "_")
	if len(parts) != 3 || parts[0] != tokenPrefix {
		return "", "", ErrMalformedToken
	}
	if parts[1] == "" || parts[2] == "" {
		return "", "", ErrMalformedToken
	}
	return parts[1], parts[2], nil
}

// HashTokenSecret hashes the secret half of a token.
//
// Plain SHA-256, not Argon2id, and that is a considered choice rather than a
// shortcut. A password hash is slow to make guessing expensive; there is
// nothing to guess here, because the secret is 256 uniformly random bits and
// no amount of hardware will enumerate that space. Meanwhile every device on
// the network authenticates on every poll, so a 64 MiB memory-hard derivation
// per request would turn a Raspberry Pi into a space heater and buy nothing.
func HashTokenSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// VerifyTokenSecret reports whether secret matches the stored hash, in
// constant time.
func VerifyTokenSecret(secret string, storedHash []byte) bool {
	if len(storedHash) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(HashTokenSecret(secret), storedHash) == 1
}
