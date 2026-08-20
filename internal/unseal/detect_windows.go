//go:build windows

package unseal

import (
	"fmt"
	"path/filepath"
)

// Detect picks the strongest provider this host supports.
//
// Le TPM quand la machine en a un, DPAPI sinon. Les deux tiennent la clé hors
// du dossier de données ; seul le TPM la tient hors du disque, ce qui est la
// différence quand quelqu'un repart avec.
//
// La sonde ne tourne qu'à l'installation, et le résultat est inscrit dans le
// slot. Un TPM qui disparaît ensuite fait échouer le démarrage bruyamment,
// plutôt que de retomber en silence sur une protection plus faible que celle
// annoncée au propriétaire.
func Detect(dataDir string) Provider {
	if windowsTPMAvailable() {
		return WindowsTPM{}
	}
	return DPAPI{}
}

// Fallback returns the provider to use if the preferred one fails to
// provision, so setup can still complete on an unusual host.
//
// DPAPI, pas un fichier : il est présent sur toute machine Windows et ne
// demande aucun matériel. Un TPM qui refuse de sceller ne doit pas faire
// dégringoler l'installation jusqu'à la clé posée en clair à côté de la base,
// alors qu'il reste une marche intermédiaire.
func Fallback(dataDir string) Provider {
	return DPAPI{}
}

// ByName resurrects the provider recorded at setup.
//
// Startup never re-runs Detect: a host that silently loses its keystore must
// fail loudly rather than quietly fall back to weaker protection, which would
// leave the owner believing in a guarantee that no longer holds.
func ByName(name, dataDir string) (Provider, error) {
	switch name {
	case "windows-tpm":
		return WindowsTPM{}, nil
	case "dpapi":
		return DPAPI{}, nil
	case "keyfile":
		return Keyfile{Path: filepath.Join(dataDir, "root.key")}, nil
	default:
		return nil, fmt.Errorf("unseal: unknown provider %q on this platform", name)
	}
}
