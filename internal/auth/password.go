// Package auth holds SYNSEC's credential primitives: passwords for people,
// tokens for machines.
//
// The two are treated very differently on purpose. A password is short, chosen
// by a human, and therefore guessable - it gets a deliberately slow key
// derivation. A machine token is 256 bits straight from the system CSPRNG and
// gets a plain hash. Applying the slow function to both would burn CPU on
// every poll from every device for no security gain whatsoever.
package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"unicode/utf8"

	"synsec/internal/crypto"
	"synsec/internal/store"
)

// MinPasswordLength is a floor, not advice.
//
// Ten characters with Argon2id behind them is a reasonable ask for a household
// server on a private network. Demanding punctuation and digits on top would
// mostly produce passwords written on a sticky note next to the machine, which
// is a worse outcome than a long simple one.
const MinPasswordLength = 10

// MaxPasswordLength bounds the work an unauthenticated caller can ask for:
// without it, a megabyte-long password would mean a megabyte-long Argon2id
// input on every login attempt.
const MaxPasswordLength = 1024

var (
	// ErrPasswordTooShort is returned when a chosen password is under
	// MinPasswordLength.
	ErrPasswordTooShort = fmt.Errorf("auth: password must be at least %d characters", MinPasswordLength)

	// ErrPasswordTooLong is returned when a password exceeds MaxPasswordLength.
	ErrPasswordTooLong = fmt.Errorf("auth: password must be under %d characters", MaxPasswordLength)
)

// HashPassword derives a verifier for a newly chosen password.
func HashPassword(password string) (store.Credentials, error) {
	return hashPasswordWith(password, crypto.DefaultArgon2)
}

// HashPasswordWith derives a verifier using explicit parameters, for hosts
// where the default 64 MiB working set is too much to ask.
func HashPasswordWith(password string, params crypto.Argon2Params) (store.Credentials, error) {
	return hashPasswordWith(password, params)
}

func hashPasswordWith(password string, params crypto.Argon2Params) (store.Credentials, error) {
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return store.Credentials{}, ErrPasswordTooShort
	}
	if len(password) > MaxPasswordLength {
		return store.Credentials{}, ErrPasswordTooLong
	}

	salt, err := crypto.NewSalt()
	if err != nil {
		return store.Credentials{}, err
	}
	hash, err := params.Derive([]byte(password), salt)
	if err != nil {
		return store.Credentials{}, fmt.Errorf("auth: hashing password: %w", err)
	}
	return store.Credentials{Hash: hash, Salt: salt, Params: params}, nil
}

// VerifyPassword reports whether password matches the stored verifier.
//
// The comparison is constant-time. Any malformed verifier is a failure rather
// than an error, so a corrupted row can never be turned into a way in.
func VerifyPassword(cred store.Credentials, password string) bool {
	if len(cred.Hash) == 0 || len(cred.Salt) == 0 {
		return false
	}
	if len(password) > MaxPasswordLength {
		return false
	}

	candidate, err := cred.Params.Derive([]byte(password), cred.Salt)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(candidate, cred.Hash) == 1
}

// NeedsRehash reports whether a stored verifier was made with weaker
// parameters than the current default, so a successful sign-in can quietly
// upgrade it.
func NeedsRehash(cred store.Credentials) bool {
	d := crypto.DefaultArgon2
	return cred.Params.Memory < d.Memory || cred.Params.Time < d.Time
}

// ErrInvalidCredentials is what callers should surface for a failed sign-in,
// whatever actually went wrong.
//
// Distinguishing "no such user" from "wrong password" would let anyone
// enumerate the accounts on the server.
var ErrInvalidCredentials = errors.New("auth: incorrect username or password")
