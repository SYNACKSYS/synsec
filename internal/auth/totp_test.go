package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// The vectors from RFC 6238, appendix B, for SHA-1.
//
// A one-time password scheme that is almost right is a scheme that works
// against its own test suite and fails against every real authenticator.
func TestTOTPMatchesRFC6238(t *testing.T) {
	secret := totpEncoding.EncodeToString([]byte("12345678901234567890"))

	cases := map[int64]string{
		59:         "287082",
		1111111109: "081804",
		1111111111: "050471",
		1234567890: "005924",
		2000000000: "279037",
	}
	for unix, want := range cases {
		at := time.Unix(unix, 0)
		if !VerifyTOTP(secret, want, at) {
			key, _ := decodeTOTPSecret(secret)
			got := totpAt(key, uint64(unix/30))
			t.Errorf("at %d the code is %q, want %q", unix, got, want)
		}
	}
}

func TestTOTPRejectsWrongCodes(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatalf("NewTOTPSecret: %v", err)
	}
	now := time.Now()

	for _, code := range []string{"", "000000", "12345", "1234567", "abcdef", "  "} {
		if VerifyTOTP(secret, code, now) {
			t.Errorf("%q was accepted", code)
		}
	}
}

// A phone's clock drifts, and a code is read a few seconds before it is typed.
// One step either side is accepted; two are not.
func TestTOTPToleratesOneStepOfDrift(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatalf("NewTOTPSecret: %v", err)
	}
	key, _ := decodeTOTPSecret(secret)

	now := time.Unix(1700000000, 0)
	counter := uint64(now.Unix() / 30)

	for _, offset := range []int64{-1, 0, 1} {
		code := totpAt(key, uint64(int64(counter)+offset))
		if !VerifyTOTP(secret, code, now) {
			t.Errorf("a code %d step away was refused", offset)
		}
	}
	for _, offset := range []int64{-3, -2, 2, 3} {
		code := totpAt(key, uint64(int64(counter)+offset))
		if VerifyTOTP(secret, code, now) {
			t.Errorf("a code %d steps away was accepted", offset)
		}
	}
}

// The secret has to survive being read off a screen and typed back with
// spaces and in the wrong case.
func TestTOTPSecretIsForgiving(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatalf("NewTOTPSecret: %v", err)
	}
	key, _ := decodeTOTPSecret(secret)
	now := time.Now()
	code := totpAt(key, uint64(now.Unix()/30))

	for _, written := range []string{
		secret,
		strings.ToLower(secret),
		FormatTOTPSecret(secret),
		" " + secret + " ",
	} {
		if !VerifyTOTP(written, code, now) {
			t.Errorf("the secret written as %q was not understood", written)
		}
	}
}

func TestTOTPSecretsAreUniqueAndWellFormed(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		secret, err := NewTOTPSecret()
		if err != nil {
			t.Fatalf("NewTOTPSecret: %v", err)
		}
		if seen[secret] {
			t.Fatal("NewTOTPSecret produced a duplicate")
		}
		seen[secret] = true

		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		if err != nil {
			t.Fatalf("the secret is not readable base32: %v", err)
		}
		if len(raw) != totpSecretBytes {
			t.Fatalf("the secret carries %d bytes, want %d", len(raw), totpSecretBytes)
		}
	}
}

// The address handed to an authenticator has to carry everything it needs, or
// the entry shows up unnamed and with the wrong period.
func TestTOTPURICarriesWhatApplicationsRead(t *testing.T) {
	uri := TOTPURI("ABCDEFGH", "SYNSEC", "cyril")

	for _, want := range []string{
		"otpauth://totp/",
		"secret=ABCDEFGH",
		"issuer=SYNSEC",
		"digits=6",
		"period=30",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("the URI lacks %q: %s", want, uri)
		}
	}
}
