//go:build !windows && !linux

package unseal

import (
	"fmt"
	"path/filepath"
)

// Detect falls back to a key file on platforms SYNSEC has no keystore binding
// for - macOS and the BSDs, today.
//
// This is a deliberate gap rather than an oversight: the target deployment is
// a Windows or Linux box on a home network. Adding a Keychain provider is a
// contained change if that ever stops being true.
func Detect(dataDir string) Provider {
	return Fallback(dataDir)
}

// Fallback returns the provider to use if the preferred one fails to
// provision, so setup can still complete on an unusual host.
func Fallback(dataDir string) Provider {
	return Keyfile{Path: filepath.Join(dataDir, "root.key")}
}

// ByName resurrects the provider recorded at setup.
func ByName(name, dataDir string) (Provider, error) {
	if name == "keyfile" {
		return Keyfile{Path: filepath.Join(dataDir, "root.key")}, nil
	}
	return nil, fmt.Errorf("unseal: unknown provider %q on this platform", name)
}
