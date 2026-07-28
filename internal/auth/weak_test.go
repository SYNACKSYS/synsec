package auth

import (
	"errors"
	"strings"
	"testing"
)

// Length alone is a poor filter: "motdepasse" is ten characters and among the
// first hundred anyone tries.
func TestCommonPasswordsAreRefused(t *testing.T) {
	for _, password := range []string{
		"motdepasse", "MotDePasse", "password123", "administrateur",
		"homeassistant", "changemenow", "0123456789",
	} {
		if err := CheckPasswordStrength(password, "cyril"); !errors.Is(err, ErrPasswordTooCommon) {
			t.Errorf("%q was accepted: %v", password, err)
		}
	}
}

// The account name is the other thing tried immediately.
func TestPasswordBuiltFromTheUsernameIsRefused(t *testing.T) {
	// All at or above the minimum length, so the refusal is about the name
	// rather than about being short.
	for _, password := range []string{"cyrilcyril", "cyrilcyril1", "cyrilcyril12"} {
		if err := CheckPasswordStrength(password, "cyrilcyril"); !errors.Is(err, ErrPasswordTooCommon) {
			t.Errorf("%q was accepted for that account: %v", password, err)
		}
	}
}

func TestRepeatedCharacterIsRefused(t *testing.T) {
	if err := CheckPasswordStrength(strings.Repeat("a", 20), "cyril"); !errors.Is(err, ErrPasswordTooCommon) {
		t.Fatalf("a single repeated character was accepted: %v", err)
	}
}

// Length is still checked, and a long ordinary passphrase still passes: the
// rule is not there to make good passwords hard to choose.
func TestReasonablePassphrasesPass(t *testing.T) {
	if err := CheckPasswordStrength("court", "cyril"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("a short password gave %v", err)
	}
	for _, password := range []string{
		"correct horse battery staple",
		"le chat du voisin dort",
		"Xk9#mQ2$vL8pR",
	} {
		if err := CheckPasswordStrength(password, "cyril"); err != nil {
			t.Errorf("%q was refused: %v", password, err)
		}
	}
}
