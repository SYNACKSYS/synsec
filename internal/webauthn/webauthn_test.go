package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// The tests build the bytes a real security key would return, sign them with a
// key generated here, and check the server reaches the same conclusion. That
// covers the parsing and the arithmetic without a stored capture of somebody's
// actual authenticator - which would go stale and could not be varied.

var testConfig = Config{RPID: "synsec.maison", Origin: "https://synsec.maison:8443"}

// A minimal CBOR writer, enough to compose what an authenticator sends.

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	default:
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	}
}

func cborUint(n uint64) []byte    { return cborHead(0, n) }
func cborNegative(n int64) []byte { return cborHead(1, uint64(-1-n)) }

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }

func cborMap(pairs ...[]byte) []byte {
	out := cborHead(5, uint64(len(pairs)/2))
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}

// signer is a key pair standing in for an authenticator.
type signer struct {
	cose []byte
	sign func(message []byte) []byte
}

func newES256(t *testing.T) *signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	x := priv.PublicKey.X.FillBytes(make([]byte, 32))
	y := priv.PublicKey.Y.FillBytes(make([]byte, 32))

	return &signer{
		cose: cborMap(
			cborUint(1), cborUint(2), // kty: EC2
			cborUint(3), cborNegative(-7), // alg: ES256
			cborNegative(-1), cborUint(1), // crv: P-256
			cborNegative(-2), cborBytes(x),
			cborNegative(-3), cborBytes(y),
		),
		sign: func(message []byte) []byte {
			sum := sha256.Sum256(message)
			sig, err := ecdsa.SignASN1(rand.Reader, priv, sum[:])
			if err != nil {
				t.Fatalf("SignASN1: %v", err)
			}
			return sig
		},
	}
}

func newRS256(t *testing.T) *signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	return &signer{
		cose: cborMap(
			cborUint(1), cborUint(3), // kty: RSA
			cborUint(3), cborNegative(-257), // alg: RS256
			cborNegative(-1), cborBytes(priv.PublicKey.N.Bytes()),
			cborNegative(-2), cborBytes([]byte{1, 0, 1}),
		),
		sign: func(message []byte) []byte {
			sum := sha256.Sum256(message)
			sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
			if err != nil {
				t.Fatalf("SignPKCS1v15: %v", err)
			}
			return sig
		},
	}
}

func newEd25519(t *testing.T) *signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	return &signer{
		cose: cborMap(
			cborUint(1), cborUint(1), // kty: OKP
			cborUint(3), cborNegative(-8), // alg: EdDSA
			cborNegative(-1), cborUint(6), // crv: Ed25519
			cborNegative(-2), cborBytes(pub),
		),
		sign: func(message []byte) []byte { return ed25519.Sign(priv, message) },
	}
}

func clientJSON(kind string, challenge []byte, origin string) []byte {
	return []byte(fmt.Sprintf(`{"type":%q,"challenge":%q,"origin":%q,"crossOrigin":false}`,
		kind, base64.RawURLEncoding.EncodeToString(challenge), origin))
}

// authData composes the block an authenticator signs.
func authDataFor(rpID string, flags byte, count uint32, credID, cose []byte) []byte {
	hash := sha256.Sum256([]byte(rpID))

	out := append([]byte(nil), hash[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, count)
	if cose == nil {
		return out
	}

	out = append(out, make([]byte, 16)...) // AAGUID
	out = binary.BigEndian.AppendUint16(out, uint16(len(credID)))
	out = append(out, credID...)
	return append(out, cose...)
}

func attestationFor(authData []byte) []byte {
	return cborMap(
		cborText("fmt"), cborText("none"),
		cborText("attStmt"), cborMap(),
		cborText("authData"), cborBytes(authData),
	)
}

// enrol runs a registration the way a browser would and returns the credential.
func enrol(t *testing.T, s *signer, challenge []byte) *Credential {
	t.Helper()

	client := clientJSON("webauthn.create", challenge, testConfig.Origin)
	data := authDataFor(testConfig.RPID, flagUserPresent|flagAttested, 0,
		[]byte("identifiant-de-credential"), s.cose)

	cred, err := VerifyRegistration(testConfig, challenge, client, attestationFor(data))
	if err != nil {
		t.Fatalf("VerifyRegistration: %v", err)
	}
	return cred
}

// assert runs a sign-in the way a browser would.
func assertWith(t *testing.T, s *signer, cred *Credential, challenge []byte, count uint32) (uint32, error) {
	t.Helper()

	client := clientJSON("webauthn.get", challenge, testConfig.Origin)
	data := authDataFor(testConfig.RPID, flagUserPresent, count, nil, nil)

	sum := sha256.Sum256(client)
	return VerifyAssertion(testConfig, *cred, challenge, client, data, s.sign(append(append([]byte(nil), data...), sum[:]...)))
}

// The three algorithms a key on sale might use must all make it through
// registration and back through a sign-in.
func TestEverySupportedAlgorithmRoundTrips(t *testing.T) {
	for name, build := range map[string]func(*testing.T) *signer{
		"ES256":   newES256,
		"RS256":   newRS256,
		"Ed25519": newEd25519,
	} {
		t.Run(name, func(t *testing.T) {
			s := build(t)
			cred := enrol(t, s, []byte("le defi de l'enregistrement"))

			if string(cred.ID) != "identifiant-de-credential" {
				t.Fatalf("the credential identifier came back as %q", cred.ID)
			}

			count, err := assertWith(t, s, cred, []byte("le defi de la connexion"), 7)
			if err != nil {
				t.Fatalf("VerifyAssertion: %v", err)
			}
			if count != 7 {
				t.Fatalf("the counter came back as %d, want 7", count)
			}
		})
	}
}

// A signature from a different key must not pass, or the check is decoration.
func TestAnotherKeyCannotAnswer(t *testing.T) {
	enrolled := newES256(t)
	impostor := newES256(t)

	cred := enrol(t, enrolled, []byte("defi"))
	if _, err := assertWith(t, impostor, cred, []byte("defi de connexion"), 1); !errors.Is(err, errBadSignature) {
		t.Fatalf("a signature from another key gave %v, want a refusal", err)
	}
}

// The challenge is what makes a captured ceremony useless a second time.
func TestAReplayedChallengeIsRefused(t *testing.T) {
	s := newES256(t)
	cred := enrol(t, s, []byte("defi"))

	client := clientJSON("webauthn.get", []byte("un autre defi"), testConfig.Origin)
	data := authDataFor(testConfig.RPID, flagUserPresent, 1, nil, nil)
	sum := sha256.Sum256(client)
	signed := append(append([]byte(nil), data...), sum[:]...)

	// The server asked for one challenge; the key answered another. The
	// signature itself is perfectly valid, which is the point.
	_, err := VerifyAssertion(testConfig, *cred, []byte("le defi attendu"), client, data, s.sign(signed))
	if !errors.Is(err, ErrChallenge) {
		t.Fatalf("an answer to another challenge gave %v, want ErrChallenge", err)
	}
}

// A phishing page on another origin is the attack security keys exist to stop.
func TestAnotherOriginIsRefused(t *testing.T) {
	s := newES256(t)
	cred := enrol(t, s, []byte("defi"))
	challenge := []byte("defi de connexion")

	client := clientJSON("webauthn.get", challenge, "https://synsec.maison.attaquant.fr")
	data := authDataFor(testConfig.RPID, flagUserPresent, 1, nil, nil)
	sum := sha256.Sum256(client)

	_, err := VerifyAssertion(testConfig, *cred, challenge, client, data,
		s.sign(append(append([]byte(nil), data...), sum[:]...)))
	if !errors.Is(err, ErrOrigin) {
		t.Fatalf("an origin that merely starts the same gave %v, want ErrOrigin", err)
	}
}

// The domain is baked into what the key signs, so a response aimed at another
// server must not be accepted here either.
func TestAnotherDomainIsRefused(t *testing.T) {
	s := newES256(t)
	cred := enrol(t, s, []byte("defi"))
	challenge := []byte("defi de connexion")

	client := clientJSON("webauthn.get", challenge, testConfig.Origin)
	data := authDataFor("autre.maison", flagUserPresent, 1, nil, nil)
	sum := sha256.Sum256(client)

	_, err := VerifyAssertion(testConfig, *cred, challenge, client, data,
		s.sign(append(append([]byte(nil), data...), sum[:]...)))
	if !errors.Is(err, ErrOrigin) {
		t.Fatalf("a response scoped to another domain gave %v, want ErrOrigin", err)
	}
}

// Everything the key signs must be covered, including the flags and counter
// that sit alongside the hash.
func TestTamperedAuthenticatorDataIsRefused(t *testing.T) {
	s := newES256(t)
	cred := enrol(t, s, []byte("defi"))
	challenge := []byte("defi de connexion")

	client := clientJSON("webauthn.get", challenge, testConfig.Origin)
	data := authDataFor(testConfig.RPID, flagUserPresent, 1, nil, nil)
	sum := sha256.Sum256(client)
	signature := s.sign(append(append([]byte(nil), data...), sum[:]...))

	tampered := append([]byte(nil), data...)
	tampered[36] = 99 // the counter

	if _, err := VerifyAssertion(testConfig, *cred, challenge, client, tampered, signature); err == nil {
		t.Fatal("altered authenticator data was accepted")
	}
}

// A counter that does not move forward is how a copied credential shows up.
func TestACounterGoingBackwardsIsRefused(t *testing.T) {
	s := newES256(t)
	cred := enrol(t, s, []byte("defi"))
	cred.SignCount = 40

	if _, err := assertWith(t, s, cred, []byte("defi de connexion"), 12); !errors.Is(err, ErrCloned) {
		t.Fatalf("a counter that went backwards gave %v, want ErrCloned", err)
	}
	// A key that keeps no counter reports zero forever, which is allowed.
	cred.SignCount = 0
	if _, err := assertWith(t, s, cred, []byte("un autre defi"), 0); err != nil {
		t.Fatalf("a key without a counter was refused: %v", err)
	}
}

// Without a touch there is no proof anybody is there, which is the one thing
// a security key is for.
func TestWithoutATouchNothingIsAccepted(t *testing.T) {
	s := newES256(t)
	challenge := []byte("defi")

	client := clientJSON("webauthn.create", challenge, testConfig.Origin)
	data := authDataFor(testConfig.RPID, flagAttested, 0, []byte("cred"), s.cose)

	if _, err := VerifyRegistration(testConfig, challenge, client, attestationFor(data)); !errors.Is(err, ErrNotPresent) {
		t.Fatalf("a registration without a touch gave %v, want ErrNotPresent", err)
	}
}

// A registration response replayed into the sign-in step must not work: the
// two ceremonies sign different things and say so in the client data.
func TestACreateResponseCannotSignIn(t *testing.T) {
	s := newES256(t)
	cred := enrol(t, s, []byte("defi"))
	challenge := []byte("defi de connexion")

	client := clientJSON("webauthn.create", challenge, testConfig.Origin)
	data := authDataFor(testConfig.RPID, flagUserPresent, 1, nil, nil)
	sum := sha256.Sum256(client)

	_, err := VerifyAssertion(testConfig, *cred, challenge, client, data,
		s.sign(append(append([]byte(nil), data...), sum[:]...)))
	if err == nil {
		t.Fatal("a registration response was accepted as a sign-in")
	}
}

// A point that is not on the curve is not a key, and verification against one
// has no defined meaning.
func TestAPointOffTheCurveIsRefused(t *testing.T) {
	cose := cborMap(
		cborUint(1), cborUint(2),
		cborUint(3), cborNegative(-7),
		cborNegative(-1), cborUint(1),
		cborNegative(-2), cborBytes(make([]byte, 32)),
		cborNegative(-3), cborBytes(make([]byte, 32)),
	)
	if _, _, err := parsePublicKey(cose); !errors.Is(err, errUnsupportedKey) {
		t.Fatalf("a point off P-256 gave %v, want a refusal", err)
	}
}

func TestUnknownAlgorithmsAreRefused(t *testing.T) {
	// ES512, which nothing here is prepared to verify.
	cose := cborMap(
		cborUint(1), cborUint(2),
		cborUint(3), cborNegative(-36),
		cborNegative(-1), cborUint(3),
	)
	if _, _, err := parsePublicKey(cose); !errors.Is(err, errUnsupportedKey) {
		t.Fatalf("an unsupported algorithm gave %v, want a refusal", err)
	}
}

// The decoder reads bytes nobody has authenticated yet, so a length field that
// lies must cost nothing.
func TestAnImpossibleLengthDoesNotAllocate(t *testing.T) {
	// A map announcing four billion entries, in five bytes.
	if _, _, err := decodeMap([]byte{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatal("a map claiming more entries than there are bytes was accepted")
	}
	// A byte string announcing sixty-four kilobytes, holding none.
	if _, _, err := decodeMap([]byte{0xa1, 0x01, 0x59, 0xff, 0xff}); err == nil {
		t.Fatal("a byte string longer than the buffer was accepted")
	}
}

func TestIndefiniteLengthsAreRefused(t *testing.T) {
	// A map with no announced size, which the specification allows and this
	// decoder deliberately does not.
	if _, _, err := decodeMap([]byte{0xbf, 0x01, 0x02, 0xff}); err == nil {
		t.Fatal("an indefinite-length map was accepted")
	}
}

// Two entries under one key leave which one wins up to the decoder, and a
// disagreement between decoders is where these bugs live.
func TestDuplicateKeysAreRefused(t *testing.T) {
	if _, _, err := decodeMap([]byte{0xa2, 0x01, 0x02, 0x01, 0x03}); err == nil {
		t.Fatal("a map with a repeated key was accepted")
	}
}

// The public key sits at the end of the authenticator data, where extensions
// may follow it. What gets stored has to be the key and nothing more.
func TestExtensionsAfterTheKeyAreNotStored(t *testing.T) {
	s := newES256(t)
	challenge := []byte("defi")

	data := authDataFor(testConfig.RPID, flagUserPresent|flagAttested, 0, []byte("cred"), s.cose)
	data = append(data, cborMap(cborText("credProtect"), cborUint(2))...)

	cred, err := VerifyRegistration(testConfig, challenge,
		clientJSON("webauthn.create", challenge, testConfig.Origin), attestationFor(data))
	if err != nil {
		t.Fatalf("VerifyRegistration: %v", err)
	}
	if len(cred.PublicKey) != len(s.cose) {
		t.Fatalf("the stored key is %d bytes, want %d - an extension came with it",
			len(cred.PublicKey), len(s.cose))
	}
}
