package store

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// idBytes gives 80 bits of entropy - far beyond what a household needs to
// avoid collisions, and short enough that an identifier stays readable in a
// URL or a log line.
const idBytes = 10

// idEncoding is base32 without padding: case-insensitive, URL-safe, and free
// of the characters people confuse when reading an identifier aloud.
var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewID returns a random identifier for a row.
//
// Random rather than sequential: identifiers show up in URLs and in service
// tokens, and a counter would leak how many vaults or devices exist.
func NewID() (string, error) {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("store: generating identifier: %w", err)
	}
	return strings.ToLower(idEncoding.EncodeToString(b)), nil
}

// MustNewID is NewID for call sites that cannot report an error. A failing
// system CSPRNG is not a condition SYNSEC can sensibly continue through.
func MustNewID() string {
	id, err := NewID()
	if err != nil {
		panic(err)
	}
	return id
}
