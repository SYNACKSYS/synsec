package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Time-based one-time passwords, RFC 6238.
//
// SHA-1 with six digits and a thirty-second step, because that is what every
// authenticator application actually implements. A stronger hash here would
// only mean codes that Google Authenticator refuses to read, and the security
// of the scheme does not rest on the digest anyway: it rests on the shared
// secret, which is 160 bits of CSPRNG output.
const (
	totpDigits = 6
	totpStep   = 30 * time.Second

	// totpSkew is how many steps either side of now are accepted. One step
	// covers the clock drift of a phone and the time between reading a code
	// and finishing the word.
	totpSkew = 1

	// totpSecretBytes is what RFC 4226 recommends, and what the applications
	// expect to be handed.
	totpSecretBytes = 20
)

// ErrInvalidTOTP means the code did not match.
var ErrInvalidTOTP = errors.New("auth: incorrect verification code")

// totpEncoding is base32 without padding, upper case: the form every
// authenticator accepts when a code is typed in by hand.
var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret mints a shared secret, encoded the way it will be shown.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, totpSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return totpEncoding.EncodeToString(raw), nil
}

// TOTPURI builds the otpauth:// address an authenticator reads.
//
// issuer appears twice on purpose: once as a label prefix, which is what old
// applications display, and once as a parameter, which is what current ones
// read. Applications that understand both show one entry, not two.
func TOTPURI(secret, issuer, account string) string {
	label := url.PathEscape(issuer + ":" + account)
	params := url.Values{
		"secret": {secret},
		"issuer": {issuer},
		"digits": {fmt.Sprint(totpDigits)},
		"period": {fmt.Sprint(int(totpStep.Seconds()))},
	}
	return "otpauth://totp/" + label + "?" + params.Encode()
}

// VerifyTOTP reports whether code matches the secret around the given moment.
//
// Compared in constant time, and every candidate step is computed before
// answering, so the time taken says nothing about which step matched or
// whether one did.
func VerifyTOTP(secret, code string, now time.Time) bool {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return false
	}

	entered := strings.TrimSpace(code)
	entered = strings.ReplaceAll(entered, " ", "")
	if len(entered) != totpDigits {
		return false
	}

	counter := uint64(now.Unix() / int64(totpStep.Seconds()))
	matched := 0
	for offset := -totpSkew; offset <= totpSkew; offset++ {
		candidate := totpAt(key, uint64(int64(counter)+int64(offset)))
		matched |= subtle.ConstantTimeCompare([]byte(candidate), []byte(entered))
	}
	return matched == 1
}

// decodeTOTPSecret reads a secret as it is stored or as someone typed it,
// spaces and lower case included.
func decodeTOTPSecret(secret string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if cleaned == "" {
		return nil, errors.New("auth: empty TOTP secret")
	}
	return totpEncoding.DecodeString(cleaned)
}

// totpAt computes the code for one counter value.
func totpAt(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation, RFC 4226 section 5.3.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%mod)
}

// FormatTOTPSecret groups a secret into blocks of four, which is how it is
// meant to be read aloud and typed in.
func FormatTOTPSecret(secret string) string {
	var b strings.Builder
	for i, r := range secret {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// TOTPCodeAt returns the code an authenticator would show at a given moment.
//
// Exported because a test needs to produce a code without searching for one,
// and because being able to ask the server what it expects is the fastest way
// to settle "is my phone's clock wrong".
func TOTPCodeAt(secret string, at time.Time) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	return totpAt(key, uint64(at.Unix()/int64(totpStep.Seconds()))), nil
}
