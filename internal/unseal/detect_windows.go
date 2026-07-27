//go:build windows

package unseal

import (
	"fmt"
	"path/filepath"
)

// Detect picks the strongest provider this host supports.
//
// On Windows that is always DPAPI: it ships with the OS, needs no hardware,
// and requires no configuration. The keyfile fallback is offered only so the
// caller can present a choice, never selected automatically.
func Detect(dataDir string) Provider {
	return DPAPI{}
}

// Fallback returns the provider to use if the preferred one fails to
// provision, so setup can still complete on an unusual host.
func Fallback(dataDir string) Provider {
	return Keyfile{Path: filepath.Join(dataDir, "root.key")}
}

// ByName resurrects the provider recorded at setup.
//
// Startup never re-runs Detect: a host that silently loses its keystore must
// fail loudly rather than quietly fall back to weaker protection, which would
// leave the owner believing in a guarantee that no longer holds.
func ByName(name, dataDir string) (Provider, error) {
	switch name {
	case "dpapi":
		return DPAPI{}, nil
	case "keyfile":
		return Keyfile{Path: filepath.Join(dataDir, "root.key")}, nil
	default:
		return nil, fmt.Errorf("unseal: unknown provider %q on this platform", name)
	}
}
