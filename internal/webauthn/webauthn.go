// Package webauthn verifies FIDO2 security keys.
//
// Written rather than imported, for the same reason the QR encoder was: SYNSEC
// ships as one executable with nothing behind it, and the two ceremonies a
// server has to perform are a page of arithmetic each. Registration reads the
// public key a key hands over; assertion checks a signature over the data that
// key was shown. Everything else in the specification is either the browser's
// job or optional.
//
// What is deliberately left out is attestation. A key's attestation statement
// answers "which make and model is this", and checking it needs a trust list
// and a metadata service to keep current. For a household server it answers
// the wrong question: whoever registers a key is already signed in, and the
// point is that this key belongs to them, not that it came from a particular
// factory.
package webauthn

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// Config is what the ceremonies are checked against: the domain the credential
// is scoped to, and the exact origin the browser must claim.
type Config struct {
	// RPID is the domain, without scheme or port - "synsec.maison" or
	// "192.168.1.20". A credential is bound to it and will not be offered to
	// any other name, which is what makes a phishing page unable to use it.
	RPID string

	// Origin is the full origin the page was served from, port included.
	Origin string
}

// Credential is a registered key, as it is stored.
type Credential struct {
	// ID is the credential identifier the key chose. It is sent back to the
	// browser at sign-in so the key knows which of its credentials to use.
	ID []byte

	// PublicKey is the COSE_Key exactly as the key encoded it. Kept in that
	// form rather than re-encoded, so what verifies a signature is the bytes
	// the authenticator produced.
	PublicKey []byte

	// SignCount is the key's own counter, when it keeps one.
	SignCount uint32

	// AAGUID identifies the make and model. Recorded because it costs nothing
	// and answers "which key is this" when someone has three.
	AAGUID []byte
}

// Authenticator data flags.
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttested     = 0x40
)

var (
	// ErrChallenge means the answer was not to the question that was asked -
	// a replayed ceremony, or one aimed at a different server.
	ErrChallenge = errors.New("webauthn: the answer does not match the challenge")

	// ErrOrigin means the page the key signed for was not this server.
	ErrOrigin = errors.New("webauthn: the origin does not match")

	// ErrNotPresent means nobody touched the key.
	ErrNotPresent = errors.New("webauthn: no user presence")

	// ErrCloned means the key's counter went backwards, which is what a copied
	// credential looks like from here.
	ErrCloned = errors.New("webauthn: the signature counter went backwards")

	errMalformed = errors.New("webauthn: malformed response")
)

// VerifyRegistration checks what a browser returned from a create ceremony and
// returns the credential to store.
func VerifyRegistration(cfg Config, challenge, clientDataJSON, attestationObject []byte) (*Credential, error) {
	if err := checkClientData(cfg, "webauthn.create", challenge, clientDataJSON); err != nil {
		return nil, err
	}

	attestation, _, err := decodeMap(attestationObject)
	if err != nil {
		return nil, err
	}
	raw := mapBytes(attestation, "authData")
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: no authenticator data", errMalformed)
	}

	data, err := parseAuthData(raw, true)
	if err != nil {
		return nil, err
	}
	if err := checkRP(cfg, data); err != nil {
		return nil, err
	}

	return &Credential{
		ID:        data.credentialID,
		PublicKey: data.publicKey,
		SignCount: data.signCount,
		AAGUID:    data.aaguid,
	}, nil
}

// VerifyAssertion checks a get ceremony against a stored credential and
// returns the counter to record.
func VerifyAssertion(cfg Config, cred Credential, challenge, clientDataJSON, authenticatorData, signature []byte) (uint32, error) {
	if err := checkClientData(cfg, "webauthn.get", challenge, clientDataJSON); err != nil {
		return 0, err
	}

	data, err := parseAuthData(authenticatorData, false)
	if err != nil {
		return 0, err
	}
	if err := checkRP(cfg, data); err != nil {
		return 0, err
	}

	key, _, err := parsePublicKey(cred.PublicKey)
	if err != nil {
		return 0, err
	}

	// What the key signed is its own authenticator data followed by the hash
	// of the client data - which is how the challenge, the origin and the
	// domain all end up covered by one signature.
	sum := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authenticatorData)+len(sum))
	signed = append(signed, authenticatorData...)
	signed = append(signed, sum[:]...)

	if err := key.verify(signed, signature); err != nil {
		return 0, err
	}

	// A counter that stands still means the key does not keep one, which is
	// common and allowed. A counter that goes backwards means two keys are
	// answering for one credential.
	if data.signCount != 0 && data.signCount <= cred.SignCount {
		return 0, ErrCloned
	}
	return data.signCount, nil
}

// clientData is the part of the ceremony the browser writes, and the only
// place the origin can be read from: the key never sees it.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func checkClientData(cfg Config, want string, challenge, raw []byte) error {
	// Capped before parsing: this is unauthenticated input at sign-in.
	if len(raw) > 4096 {
		return fmt.Errorf("%w: client data too long", errMalformed)
	}

	var data clientData
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("%w: unreadable client data", errMalformed)
	}
	if data.Type != want {
		// A create response replayed into a sign-in, or the reverse.
		return fmt.Errorf("%w: %q where %q was expected", errMalformed, data.Type, want)
	}

	got, err := base64.RawURLEncoding.DecodeString(data.Challenge)
	if err != nil {
		return ErrChallenge
	}
	if subtle.ConstantTimeCompare(got, challenge) != 1 {
		return ErrChallenge
	}

	// Compared whole, scheme and port included. A prefix comparison would
	// accept https://synsec.maison.attaquant.fr.
	if data.Origin != cfg.Origin {
		return ErrOrigin
	}
	return nil
}

// authData is the fixed-layout block the key itself signs.
type authData struct {
	rpIDHash     []byte
	flags        byte
	signCount    uint32
	aaguid       []byte
	credentialID []byte
	publicKey    []byte
}

// parseAuthData reads the block. attested says whether a credential is
// expected in it, which is true at registration and false afterwards.
func parseAuthData(raw []byte, attested bool) (*authData, error) {
	const header = 37 // 32 of hash, one of flags, four of counter
	if len(raw) < header {
		return nil, fmt.Errorf("%w: authenticator data too short", errMalformed)
	}

	data := &authData{
		rpIDHash:  raw[:32],
		flags:     raw[32],
		signCount: binary.BigEndian.Uint32(raw[33:header]),
	}

	// Presence is the whole point of a security key: it says a human touched
	// this object. Verification - a PIN or a fingerprint - is not required
	// here, because the password was already the other factor.
	if data.flags&flagUserPresent == 0 {
		return nil, ErrNotPresent
	}
	if !attested {
		return data, nil
	}

	if data.flags&flagAttested == 0 {
		return nil, fmt.Errorf("%w: no credential in the registration", errMalformed)
	}
	rest := raw[header:]
	if len(rest) < 18 {
		return nil, fmt.Errorf("%w: truncated credential", errMalformed)
	}

	data.aaguid = rest[:16]
	length := int(binary.BigEndian.Uint16(rest[16:18]))
	// The specification caps a credential identifier at 1023 bytes.
	if length == 0 || length > 1023 || len(rest) < 18+length {
		return nil, fmt.Errorf("%w: implausible credential identifier", errMalformed)
	}
	data.credentialID = rest[18 : 18+length]

	// The key is followed by extensions when the browser asked for any, so its
	// own length decides where it stops. Parsed here rather than at the first
	// sign-in: storing a key nobody can verify would enrol an account into a
	// second factor that can never be satisfied.
	key := rest[18+length:]
	_, size, err := parsePublicKey(key)
	if err != nil {
		return nil, err
	}
	data.publicKey = key[:size]
	return data, nil
}

// checkRP holds the response to the domain it was scoped to.
func checkRP(cfg Config, data *authData) error {
	want := sha256.Sum256([]byte(cfg.RPID))
	if subtle.ConstantTimeCompare(data.rpIDHash, want[:]) != 1 {
		return ErrOrigin
	}
	return nil
}

// UserVerified reports whether the key checked a PIN or a fingerprint as well
// as a touch. Recorded rather than required: the password came first.
func UserVerified(authenticatorData []byte) bool {
	return len(authenticatorData) > 32 && authenticatorData[32]&flagUserVerified != 0
}
