package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// We use XChaCha20-Poly1305 rather than AES-GCM for two reasons: its 192-bit
// nonce can be drawn at random without any risk of collision (no counter to
// persist, no state to corrupt across restarts), and it stays fast on hardware
// without AES-NI - a Raspberry Pi running Home Assistant, typically.
const (
	// blobVersion prefixes every ciphertext so the format can evolve without
	// leaving old data unreadable.
	blobVersion byte = 0x01

	nonceSize = chacha20poly1305.NonceSizeX // 24
	tagSize   = chacha20poly1305.Overhead   // 16
	blobFixed = 1 + nonceSize + tagSize
)

// ErrDecrypt is returned whenever a blob fails to authenticate. It is
// deliberately opaque: distinguishing "wrong key" from "tampered ciphertext"
// would hand an attacker an oracle.
var ErrDecrypt = errors.New("crypto: decryption failed")

// seal encrypts plaintext under k, binding the result to aad.
//
// Layout: version(1) | nonce(24) | ciphertext | tag(16)
func seal(k *Key, aad, plaintext []byte) ([]byte, error) {
	if k.Zeroed() {
		return nil, ErrKeyZeroed
	}
	aead, err := chacha20poly1305.NewX(k.Bytes())
	if err != nil {
		return nil, fmt.Errorf("crypto: initialising cipher: %w", err)
	}

	blob := make([]byte, 1+nonceSize, blobFixed+len(plaintext))
	blob[0] = blobVersion
	nonce := blob[1 : 1+nonceSize]
	if err := randomBytes(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(blob, nonce, plaintext, aad), nil
}

// open reverses seal. It returns ErrDecrypt unless the blob was produced by
// the same key and the exact same aad.
func open(k *Key, aad, blob []byte) ([]byte, error) {
	if k.Zeroed() {
		return nil, ErrKeyZeroed
	}
	if len(blob) < blobFixed || blob[0] != blobVersion {
		return nil, ErrDecrypt
	}
	aead, err := chacha20poly1305.NewX(k.Bytes())
	if err != nil {
		return nil, fmt.Errorf("crypto: initialising cipher: %w", err)
	}

	nonce := blob[1 : 1+nonceSize]
	plaintext, err := aead.Open(nil, nonce, blob[1+nonceSize:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// bindAAD builds the additional authenticated data that ties a ciphertext to
// the exact place it belongs.
//
// Parts are length-prefixed rather than concatenated, because plain
// concatenation is ambiguous: "ab"+"c" and "a"+"bc" would produce identical
// AAD, letting an attacker with write access to the database move a ciphertext
// between two locations whose fields happen to line up.
func bindAAD(domain string, parts ...string) []byte {
	out := make([]byte, 0, 32)
	out = appendPart(out, []byte(domain))
	for _, p := range parts {
		out = appendPart(out, []byte(p))
	}
	return out
}

func appendPart(dst, p []byte) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(p)))
	return append(dst, p...)
}
