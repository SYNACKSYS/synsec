package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"
)

// Session lifetimes.
//
// SessionIdle is how long a browser may sit untouched before it is signed out.
// Every request pushes it back, so an interface being used never lapses: what
// dies is the tab left open on an unlocked machine, which is the case worth
// worrying about for something holding passwords.
//
// SessionMax is the hard stop that no amount of activity can extend, so a
// session held open for months eventually asks for a password again.
const (
	SessionIdle = 30 * time.Minute
	SessionMax  = 30 * 24 * time.Hour
)

// Bounds accepted for a configured idle timeout.
//
// Below a minute nobody could finish typing a password; above a month the
// setting stops meaning anything.
const (
	MinSessionIdle = time.Minute
	MaxSessionIdle = 30 * 24 * time.Hour
)

// sessionTokenBytes gives 256 bits, the same margin as a service token.
const sessionTokenBytes = 32

// NewSessionToken mints a session token and the hash to store against it.
//
// Base64 URL encoding keeps the cookie value free of characters that would
// need escaping.
func NewSessionToken() (token string, hash []byte, err error) {
	raw := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashSessionToken(token), nil
}

// HashSessionToken hashes a session token for storage and lookup.
//
// SHA-256 for the same reason as service tokens: the input is high-entropy
// random, so there is nothing for a slow hash to protect against, and this
// runs on every single request a signed-in browser makes.
//
// A bare digest rather than a keyed one on purpose. This is a lookup key, not
// a message authentication code: there is no secret prefix, nothing is
// authenticated by the result, and appending to a token yields a row that does
// not exist. Where a MAC is what is wanted - the CSRF token, the pending
// sign-in - the code uses HMAC.
func HashSessionToken(token string) []byte {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return sum[:]
}

// SessionExpiry returns when a session refreshed now should lapse, never
// letting an idle extension push past the absolute ceiling.
func SessionExpiry(createdAt, now time.Time) time.Time {
	return SessionExpiryWith(SessionIdle, createdAt, now)
}

// SessionExpiryWith does the same for a server running a configured timeout.
func SessionExpiryWith(idle time.Duration, createdAt, now time.Time) time.Time {
	if idle <= 0 {
		idle = SessionIdle
	}
	lapse := now.Add(idle)
	hard := createdAt.Add(SessionMax)
	if lapse.After(hard) {
		return hard
	}
	return lapse
}

// ClampSessionIdle keeps a configured value inside what the interface can
// honour, so a typo in a service unit degrades to the default rather than
// locking everyone out on the next click.
func ClampSessionIdle(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return SessionIdle
	case d < MinSessionIdle:
		return MinSessionIdle
	case d > MaxSessionIdle:
		return MaxSessionIdle
	default:
		return d
	}
}
