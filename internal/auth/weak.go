package auth

import (
	"errors"
	"strings"
)

// ErrPasswordTooCommon is returned for a password that appears in the list
// below, or that is simply the account name.
var ErrPasswordTooCommon = errors.New("auth: password is too easily guessed")

// weakPasswords is a short list of what credential-stuffing tries first.
//
// Not a breach database: SYNSEC works offline and will not call an API to ask
// about someone's password. A few dozen entries catch the cases that a lockout
// would otherwise have to absorb, and cost nothing.
//
// Length alone is a poor filter. "motdepasse" is ten characters and would pass
// the minimum while being among the first hundred anyone tries.
var weakPasswords = map[string]bool{
	"motdepasse":       true,
	"motdepasse1":      true,
	"motdepasse123":    true,
	"password":         true,
	"password1":        true,
	"password123":      true,
	"passw0rd":         true,
	"p@ssw0rd":         true,
	"azertyuiop":       true,
	"qwertyuiop":       true,
	"1234567890":       true,
	"123456789":        true,
	"12345678910":      true,
	"administrateur":   true,
	"administrator":    true,
	"changeme":         true,
	"changemenow":      true,
	"letmein123":       true,
	"iloveyou123":      true,
	"welcome123":       true,
	"bienvenue":        true,
	"soleil123":        true,
	"jetaime123":       true,
	"synsec":           true,
	"synsec123":        true,
	"secret123":        true,
	"domotique":        true,
	"homeassistant":    true,
	"raspberry":        true,
	"raspberrypi":      true,
	"qwertyuiop123":    true,
	"azertyuiop123":    true,
	"abcdefghij":       true,
	"0123456789":       true,
	"loulou123":        true,
	"doudou123":        true,
	"chouchou123":      true,
	"francefrance":     true,
	"parisparis":       true,
	"marseille13":      true,
	"olympique13":      true,
	"password1234":     true,
	"motdepasse1234":   true,
	"administrateur1":  true,
	"jesuisunmotdepas": true,
}

// CheckPasswordStrength refuses what guessing tries first.
//
// Deliberately not a complexity rule. Demanding a capital, a digit and a
// symbol produces "Password1!" and a sticky note; refusing the few hundred
// strings everyone actually picks costs nothing and catches more.
func CheckPasswordStrength(password, username string) error {
	if len(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	if len(password) > MaxPasswordLength {
		return ErrPasswordTooLong
	}

	folded := strings.ToLower(strings.TrimSpace(password))
	if weakPasswords[folded] {
		return ErrPasswordTooCommon
	}

	// The account name, on its own or with a couple of characters glued on,
	// is the other thing tried immediately.
	if name := strings.ToLower(strings.TrimSpace(username)); name != "" {
		if folded == name || strings.HasPrefix(folded, name) && len(folded) <= len(name)+3 {
			return ErrPasswordTooCommon
		}
	}

	// A single repeated character passes every length rule and no guess list.
	if repeatedRune(folded) {
		return ErrPasswordTooCommon
	}
	return nil
}

// repeatedRune reports a password made of one character over and over.
func repeatedRune(s string) bool {
	if s == "" {
		return false
	}
	first := []rune(s)[0]
	for _, r := range s {
		if r != first {
			return false
		}
	}
	return true
}
