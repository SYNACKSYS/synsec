package vault

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// A recovery code is 120 bits, which encodes to exactly 24 base32 characters
// with no padding - six groups of four, short enough to be printed on a card
// and typed back in without despair.
const (
	recoveryBytes  = 15
	recoveryGroup  = 4
	recoveryGroups = 6
)

// recoveryAlphabet is Crockford's base32: it drops I, L, O and U, the letters
// people misread as 1, 1, 0 and each other when copying a code off paper.
const recoveryAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var recoveryEncoding = base32.NewEncoding(recoveryAlphabet).WithPadding(base32.NoPadding)

// NewRecoveryCode draws a fresh recovery code, formatted for printing.
//
// This is the only thing standing between a household and the permanent loss
// of every secret when a machine dies or a service account changes, so it is
// generated during setup whether the owner asks for it or not.
func NewRecoveryCode() (string, error) {
	b := make([]byte, recoveryBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("vault: generating recovery code: %w", err)
	}

	raw := recoveryEncoding.EncodeToString(b)
	groups := make([]string, 0, recoveryGroups)
	for i := 0; i < len(raw); i += recoveryGroup {
		groups = append(groups, raw[i:i+recoveryGroup])
	}
	return strings.Join(groups, "-"), nil
}

// NormalizeRecoveryCode turns whatever the owner typed into the canonical form
// the key derivation expects.
//
// Dashes, spaces and case are ignored, and the three characters Crockford's
// alphabet excludes are folded onto the digits they get mistaken for. Someone
// reading a code aloud over the phone should not be defeated by the difference
// between the letter O and the digit zero.
func NormalizeRecoveryCode(s string) string {
	var b strings.Builder
	b.Grow(recoveryBytes * 2)

	for _, r := range strings.ToUpper(s) {
		switch r {
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		case 'U':
			r = 'V'
		}
		if strings.ContainsRune(recoveryAlphabet, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// validRecoveryCode reports whether s has the right shape once normalised.
// It says nothing about whether the code actually opens the vault.
func validRecoveryCode(s string) bool {
	return len(NormalizeRecoveryCode(s)) == recoveryGroup*recoveryGroups
}
