package store

import (
	"errors"
	"fmt"
	"unicode"
)

// The rule for everything a person writes and later reads back.
//
// A vault's name, a secret's label, a device's name, the name shown for an
// account: four fields with one job, so one rule. They are labels, not
// identifiers - accents, spaces and apostrophes belong in them - but they end
// up side by side in lists, in the audit log and in the pages that offer to
// delete them by name, and a label nobody can read or retype is a label that
// cannot be managed.
//
// Written as a list of what is allowed. A list of forbidden characters is a
// list somebody eventually finds a gap in; this one has no gap by
// construction.

const (
	// MaxLabelLength bounds every human-readable label, counted in characters
	// so an accent costs the same as a letter.
	MaxLabelLength = 60

	// MaxUsernameLength bounds the name someone signs in with. Shorter and
	// stricter than a label: it is typed at a prompt, appears in the audit log
	// beside every action, and is compared for uniqueness.
	MaxUsernameLength = 32
)

// ErrLabel says a label was refused, so a caller can tell it apart from a
// database failure or a name already taken.
var ErrLabel = errors.New("store: libellé refusé")

// ValidLabel reports whether a human-readable label may be written. what names
// the field, so the message says which one was wrong.
func ValidLabel(what, text string) error {
	runes := []rune(text)
	if len(runes) > MaxLabelLength {
		return fmt.Errorf("%w : %s dépasse %d caractères", ErrLabel, what, MaxLabelLength)
	}
	for _, r := range runes {
		if !labelRune(r) {
			return fmt.Errorf("%w : %s contient %q, qui n'y a pas sa place", ErrLabel, what, r)
		}
	}
	return nil
}

// ValidUsername reports whether an account may be called this.
//
// Stricter than a label on purpose: no spaces, no accents, nothing that looks
// different from what it is. Two accounts whose names differ only by an accent
// or a look-alike character would be two accounts nobody can tell apart in a
// journal.
func ValidUsername(name string) error {
	runes := []rune(name)
	switch {
	case len(runes) == 0:
		return fmt.Errorf("%w : le nom d'utilisateur est vide", ErrLabel)
	case len(runes) > MaxUsernameLength:
		return fmt.Errorf("%w : le nom d'utilisateur dépasse %d caractères",
			ErrLabel, MaxUsernameLength)
	}
	for _, r := range runes {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("%w : le nom d'utilisateur ne prend que des lettres non "+
				"accentuées, des chiffres, et - _ .", ErrLabel)
		}
	}
	return nil
}

// labelRune reports whether one character belongs in a label.
func labelRune(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return true
	}
	switch r {
	case ' ', '-', '_', '\'', '.', ',', '(', ')', '[', ']', '{', '}', '@', '$', '&':
		return true
	case '’': // the typographic apostrophe a phone keyboard produces
		return true
	}
	return false
}
