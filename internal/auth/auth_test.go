package auth

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"synsec/internal/crypto"
	"synsec/internal/store"
)

// fastArgon2 keeps these tests quick; production uses crypto.DefaultArgon2.
var fastArgon2 = crypto.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}

func TestPasswordRoundTrip(t *testing.T) {
	cred, err := HashPasswordWith("correct horse battery", fastArgon2)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}

	if !VerifyPassword(cred, "correct horse battery") {
		t.Fatal("the right password was rejected")
	}
	if VerifyPassword(cred, "correct horse batterz") {
		t.Fatal("a wrong password was accepted")
	}
}

// Two accounts with the same password must not share a hash, or a database
// dump would reveal which users chose the same one.
func TestPasswordsAreSalted(t *testing.T) {
	a, err := HashPasswordWith("correct horse battery", fastArgon2)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	b, err := HashPasswordWith("correct horse battery", fastArgon2)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}

	if bytes.Equal(a.Salt, b.Salt) {
		t.Fatal("two hashes of the same password share a salt")
	}
	if bytes.Equal(a.Hash, b.Hash) {
		t.Fatal("two hashes of the same password are identical")
	}
}

func TestPasswordLengthLimits(t *testing.T) {
	if _, err := HashPassword("court"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("a short password returned %v, want ErrPasswordTooShort", err)
	}
	if _, err := HashPassword(strings.Repeat("a", MaxPasswordLength+1)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("an oversized password returned %v, want ErrPasswordTooLong", err)
	}

	// The floor counts characters, not bytes: an accented password should not
	// be judged longer than it looks.
	if _, err := HashPasswordWith("éèêëàâäîïô", fastArgon2); err != nil {
		t.Fatalf("a ten-character accented password was rejected: %v", err)
	}
}

// A corrupted or empty verifier must fail closed, never open.
func TestBrokenCredentialsNeverVerify(t *testing.T) {
	good, err := HashPasswordWith("correct horse battery", fastArgon2)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}

	broken := map[string]store.Credentials{
		"empty":          {},
		"no hash":        {Salt: good.Salt, Params: fastArgon2},
		"no salt":        {Hash: good.Hash, Params: fastArgon2},
		"zero params":    {Hash: good.Hash, Salt: good.Salt},
		"truncated salt": {Hash: good.Hash, Salt: good.Salt[:4], Params: fastArgon2},
	}
	for name, cred := range broken {
		t.Run(name, func(t *testing.T) {
			if VerifyPassword(cred, "correct horse battery") {
				t.Fatal("a broken verifier accepted a password")
			}
			if VerifyPassword(cred, "") {
				t.Fatal("a broken verifier accepted an empty password")
			}
		})
	}
}

func TestNeedsRehash(t *testing.T) {
	weak, err := HashPasswordWith("correct horse battery", fastArgon2)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	if !NeedsRehash(weak) {
		t.Fatal("a verifier below the default cost was not flagged for upgrade")
	}

	current, err := HashPasswordWith("correct horse battery", crypto.DefaultArgon2)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	if NeedsRehash(current) {
		t.Fatal("a verifier at the default cost was flagged for upgrade")
	}
}

func TestServiceTokenRoundTrip(t *testing.T) {
	plaintext, hash, err := NewServiceToken("abc123")
	if err != nil {
		t.Fatalf("NewServiceToken: %v", err)
	}
	if !strings.HasPrefix(plaintext, "syn_abc123_") {
		t.Fatalf("token %q does not carry its identifier in clear", plaintext)
	}

	id, secret, err := ParseServiceToken(plaintext)
	if err != nil {
		t.Fatalf("ParseServiceToken: %v", err)
	}
	if id != "abc123" {
		t.Fatalf("parsed identifier %q, want abc123", id)
	}
	if !VerifyTokenSecret(secret, hash) {
		t.Fatal("the freshly minted secret did not verify")
	}
	if VerifyTokenSecret(secret+"x", hash) {
		t.Fatal("an altered secret verified")
	}
}

func TestServiceTokensAreUnique(t *testing.T) {
	seen := make(map[string]bool, 200)
	for i := 0; i < 200; i++ {
		plaintext, _, err := NewServiceToken("abc123")
		if err != nil {
			t.Fatalf("NewServiceToken: %v", err)
		}
		if seen[plaintext] {
			t.Fatal("NewServiceToken produced a duplicate")
		}
		seen[plaintext] = true
	}
}

func TestMalformedTokensAreRejected(t *testing.T) {
	for name, bad := range map[string]string{
		"empty":         "",
		"no prefix":     "abc123_secret",
		"wrong prefix":  "xyz_abc123_secret",
		"missing parts": "syn_abc123",
		"empty id":      "syn__secret",
		"empty secret":  "syn_abc123_",
		"too many":      "syn_abc_123_secret",
		"just words":    "not a token at all",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseServiceToken(bad); !errors.Is(err, ErrMalformedToken) {
				t.Fatalf("%q returned %v, want ErrMalformedToken", bad, err)
			}
		})
	}
}

func TestVerifyTokenSecretRejectsBadHashes(t *testing.T) {
	_, hash, err := NewServiceToken("abc123")
	if err != nil {
		t.Fatalf("NewServiceToken: %v", err)
	}
	for name, h := range map[string][]byte{
		"nil":       nil,
		"empty":     {},
		"truncated": hash[:16],
		"too long":  append(append([]byte{}, hash...), 0),
	} {
		t.Run(name, func(t *testing.T) {
			if VerifyTokenSecret("whatever", h) {
				t.Fatal("a malformed stored hash verified")
			}
		})
	}
}

func TestSessionTokenRoundTrip(t *testing.T) {
	token, hash, err := NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken: %v", err)
	}
	if !bytes.Equal(HashSessionToken(token), hash) {
		t.Fatal("hashing the token again gave a different result")
	}
	if bytes.Equal(HashSessionToken(token+"x"), hash) {
		t.Fatal("an altered token hashed to the same value")
	}

	// Cookies pick up stray whitespace on their way through proxies.
	if !bytes.Equal(HashSessionToken(" "+token+"\n"), hash) {
		t.Fatal("surrounding whitespace changed the hash")
	}
}

func TestSessionTokensAreUnique(t *testing.T) {
	seen := make(map[string]bool, 200)
	for i := 0; i < 200; i++ {
		token, _, err := NewSessionToken()
		if err != nil {
			t.Fatalf("NewSessionToken: %v", err)
		}
		if seen[token] {
			t.Fatal("NewSessionToken produced a duplicate")
		}
		seen[token] = true
	}
}

// Idle refreshes keep a kitchen tablet signed in, but must never push a
// session past its absolute ceiling.
func TestSessionExpiryRespectsTheHardCeiling(t *testing.T) {
	created := time.Now()

	early := SessionExpiry(created, created)
	if want := created.Add(SessionIdle); !early.Equal(want) {
		t.Fatalf("a fresh session expires at %v, want %v", early, want)
	}

	// Refreshed just under the ceiling, the extension is cut short rather than
	// carrying the session past it.
	late := SessionExpiry(created, created.Add(SessionMax-time.Minute))
	if want := created.Add(SessionMax); !late.Equal(want) {
		t.Fatalf("a long-lived session expires at %v, want the ceiling %v", late, want)
	}
	if late.After(created.Add(SessionMax)) {
		t.Fatal("an idle refresh pushed a session past its ceiling")
	}
}

// A configured timeout replaces the default without touching the ceiling.
func TestSessionExpiryWithAConfiguredIdle(t *testing.T) {
	created := time.Now()

	got := SessionExpiryWith(2*time.Hour, created, created)
	if want := created.Add(2 * time.Hour); !got.Equal(want) {
		t.Fatalf("expiry is %v, want %v", got, want)
	}

	// Nonsense falls back rather than producing a session already expired.
	if got := SessionExpiryWith(0, created, created); !got.Equal(created.Add(SessionIdle)) {
		t.Fatalf("a zero timeout gave %v", got)
	}

	beyond := SessionExpiryWith(365*24*time.Hour, created, created)
	if want := created.Add(SessionMax); !beyond.Equal(want) {
		t.Fatalf("a timeout longer than the ceiling gave %v, want %v", beyond, want)
	}
}

// A typo in a service unit must degrade, never lock everyone out on the next
// click.
func TestClampSessionIdle(t *testing.T) {
	cases := map[time.Duration]time.Duration{
		0:                    SessionIdle,
		-time.Hour:           SessionIdle,
		time.Second:          MinSessionIdle,
		45 * time.Minute:     45 * time.Minute,
		365 * 24 * time.Hour: MaxSessionIdle,
	}
	for given, want := range cases {
		if got := ClampSessionIdle(given); got != want {
			t.Errorf("ClampSessionIdle(%v) = %v, want %v", given, got, want)
		}
	}
}
