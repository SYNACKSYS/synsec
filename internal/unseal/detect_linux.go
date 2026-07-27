//go:build linux

package unseal

import (
	"fmt"
	"path/filepath"
)

// Detect picks the strongest provider this host supports: the TPM when there
// is one, a plain key file otherwise.
//
// The probe runs once at setup and the result is recorded in the
// configuration, so a TPM that goes missing later surfaces as a clear startup
// error rather than a silent downgrade to weaker protection.
func Detect(dataDir string) Provider {
	if systemdTPM2Available() {
		return SystemdTPM2{}
	}
	return Fallback(dataDir)
}

// Fallback returns the provider to use if the preferred one fails to
// provision, so setup can still complete on an unusual host.
func Fallback(dataDir string) Provider {
	return Keyfile{Path: filepath.Join(dataDir, "root.key")}
}

// ByName resurrects the provider recorded at setup.
//
// Startup never re-runs Detect: a host that silently loses its TPM must fail
// loudly rather than quietly fall back to a key file, which would leave the
// owner believing in a guarantee that no longer holds.
func ByName(name, dataDir string) (Provider, error) {
	switch name {
	case "systemd-tpm2":
		return SystemdTPM2{}, nil
	case "keyfile":
		return Keyfile{Path: filepath.Join(dataDir, "root.key")}, nil
	default:
		return nil, fmt.Errorf("unseal: unknown provider %q on this platform", name)
	}
}
