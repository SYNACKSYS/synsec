package webauthn

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// The public key a security key hands over is a COSE_Key: a small CBOR map
// whose entries are numbered rather than named.
//
// Three algorithms are accepted, which between them cover everything sold:
// ES256 on every FIDO2 key made, RS256 on the Windows Hello implementations
// backed by an older TPM, and Ed25519 on the SoloKeys and a few others.
const (
	ktyOKP = 1
	ktyEC2 = 2
	ktyRSA = 3

	algES256 = -7
	algEdDSA = -8
	algRS256 = -257

	crvP256    = 1
	crvEd25519 = 6
)

// COSE_Key labels. The negative ones are algorithm-specific: on an elliptic
// curve key they are the curve and the two coordinates, on an RSA key the
// modulus and the exponent.
const (
	labelKty = int64(1)
	labelAlg = int64(3)
	labelCrv = int64(-1)
	labelN   = int64(-1)
	labelX   = int64(-2)
	labelE   = int64(-2)
	labelY   = int64(-3)
)

var (
	errUnsupportedKey = errors.New("webauthn: unsupported key type")
	errBadSignature   = errors.New("webauthn: signature does not verify")
)

// publicKey is a parsed COSE_Key, ready to check a signature.
type publicKey struct {
	alg    int64
	ecdsa  *ecdsa.PublicKey
	rsa    *rsa.PublicKey
	ed     ed25519.PublicKey
	verify func(signed, signature []byte) error
}

// parsePublicKey reads a COSE_Key from the front of data and reports how many
// bytes it occupied.
//
// The length matters: the key sits at the end of the authenticator data, where
// it may be followed by extensions, and what gets stored has to be the key and
// nothing else.
func parsePublicKey(data []byte) (*publicKey, int, error) {
	m, size, err := decodeMap(data)
	if err != nil {
		return nil, 0, err
	}

	kty, ok := mapInt(m, labelKty)
	if !ok {
		return nil, 0, fmt.Errorf("%w: no key type", errUnsupportedKey)
	}
	alg, ok := mapInt(m, labelAlg)
	if !ok {
		return nil, 0, fmt.Errorf("%w: no algorithm", errUnsupportedKey)
	}

	var key *publicKey
	switch {
	case kty == ktyEC2 && alg == algES256:
		key, err = parseES256(m)
	case kty == ktyRSA && alg == algRS256:
		key, err = parseRS256(m)
	case kty == ktyOKP && alg == algEdDSA:
		key, err = parseEd25519(m)
	default:
		return nil, 0, fmt.Errorf("%w: type %d algorithm %d", errUnsupportedKey, kty, alg)
	}
	if err != nil {
		return nil, 0, err
	}

	key.alg = alg
	return key, size, nil
}

func parseES256(m map[any]any) (*publicKey, error) {
	if crv, _ := mapInt(m, labelCrv); crv != crvP256 {
		return nil, fmt.Errorf("%w: ES256 on a curve that is not P-256", errUnsupportedKey)
	}
	x, y := mapBytes(m, labelX), mapBytes(m, labelY)
	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("%w: P-256 coordinates of the wrong size", errUnsupportedKey)
	}

	// Validated through crypto/ecdh, which refuses a point that is not on the
	// curve. A key off the curve is not a key: verification against it has no
	// defined meaning, and accepting one is how signature checks get skipped.
	point := make([]byte, 0, 65)
	point = append(point, 4)
	point = append(point, x...)
	point = append(point, y...)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return nil, fmt.Errorf("%w: the point is not on P-256", errUnsupportedKey)
	}

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	return &publicKey{ecdsa: pub, verify: func(signed, signature []byte) error {
		sum := sha256.Sum256(signed)
		// The signature arrives as an ASN.1 SEQUENCE of two integers, which is
		// what VerifyASN1 expects; it also rejects any trailing rubbish.
		if !ecdsa.VerifyASN1(pub, sum[:], signature) {
			return errBadSignature
		}
		return nil
	}}, nil
}

func parseRS256(m map[any]any) (*publicKey, error) {
	modulus, exponent := mapBytes(m, labelN), mapBytes(m, labelE)
	// 2048 to 4096 bits. Anything smaller is not a key worth trusting and
	// anything larger is a denial of service dressed as a credential.
	if len(modulus) < 256 || len(modulus) > 512 || len(exponent) == 0 || len(exponent) > 4 {
		return nil, fmt.Errorf("%w: RSA parameters out of range", errUnsupportedKey)
	}

	e := new(big.Int).SetBytes(exponent)
	if !e.IsInt64() || e.Int64() < 3 || e.Int64()%2 == 0 {
		return nil, fmt.Errorf("%w: unusable RSA exponent", errUnsupportedKey)
	}

	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(e.Int64())}
	return &publicKey{rsa: pub, verify: func(signed, signature []byte) error {
		sum := sha256.Sum256(signed)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], signature); err != nil {
			return errBadSignature
		}
		return nil
	}}, nil
}

func parseEd25519(m map[any]any) (*publicKey, error) {
	if crv, _ := mapInt(m, labelCrv); crv != crvEd25519 {
		return nil, fmt.Errorf("%w: EdDSA on a curve that is not Ed25519", errUnsupportedKey)
	}
	x := mapBytes(m, labelX)
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 key of the wrong size", errUnsupportedKey)
	}

	pub := ed25519.PublicKey(append([]byte(nil), x...))
	return &publicKey{ed: pub, verify: func(signed, signature []byte) error {
		// Ed25519 hashes internally, so the message is passed whole.
		if !ed25519.Verify(pub, signed, signature) {
			return errBadSignature
		}
		return nil
	}}, nil
}
