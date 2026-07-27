package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"synsec/internal/config"
	"synsec/internal/tlsconf"
)

func runCert(args []string) error {
	if len(args) == 0 {
		return usageCert()
	}

	switch args[0] {
	case "trust", "confiance":
		return runCertTrust(args[1:])
	case "show", "path", "voir":
		return runCertShow(args[1:])
	case "-h", "--help", "help":
		return usageCert()
	default:
		return fmt.Errorf("sous-commande inconnue : cert %q", args[0])
	}
}

func usageCert() error {
	fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec cert - gère le certificat du serveur

  synsec cert trust   Installe l'autorité SYNSEC dans le magasin de la machine
  synsec cert show    Affiche l'emplacement et l'empreinte de l'autorité

Une fois l'autorité installée, le navigateur n'affiche plus d'avertissement et
PowerShell n'a plus besoin de contournement.
`)+"\n")
	return nil
}

func runCertShow(args []string) error {
	fs := flag.NewFlagSet("cert show", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}

	cfg := config.Default()
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}

	local, err := tlsconf.EnsureLocal(cfg.DataDir)
	if err != nil {
		return err
	}

	fmt.Printf("Certificat SYNSEC : %s\n", local.TrustPath)
	fmt.Printf("Empreinte SHA-256 : %s\n", local.Fingerprint)
	fmt.Println()
	fmt.Println("Pour le faire accepter par cette machine :")
	fmt.Println("  synsec cert trust")
	fmt.Println()
	fmt.Println("Pour une autre machine du réseau, copie ce fichier et installe-le")
	fmt.Println("dans ses autorités de confiance.")
	fmt.Println()
	fmt.Println("Firefox gère son propre magasin et ignore celui de Windows :")
	fmt.Println("il faut l'y importer séparément (Paramètres / Vie privée / Certificats).")
	return nil
}

func runCertTrust(args []string) error {
	fs := flag.NewFlagSet("cert trust", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}

	cfg := config.Default()
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if err := cfg.Prepare(); err != nil {
		return err
	}

	local, err := tlsconf.EnsureLocal(cfg.DataDir)
	if err != nil {
		return err
	}

	path, err := filepath.Abs(local.TrustPath)
	if err != nil {
		path = local.TrustPath
	}

	if err := installTrust(path); err != nil {
		return err
	}

	fmt.Println("Certificat SYNSEC installé dans les autorités de confiance de cette machine.")
	fmt.Printf("Empreinte SHA-256 : %s\n", local.Fingerprint)
	fmt.Println()
	fmt.Println("Ferme et rouvre Edge : l'avertissement de sécurité doit avoir disparu.")
	fmt.Println("Firefox gère son propre magasin, il faudra l'y importer à part.")
	return nil
}

// installTrust adds the authority to the machine's trust store.
//
// Shelling out to the platform's own tool rather than manipulating the store
// directly: certutil ships with Windows and update-ca-certificates with every
// Debian-derived Linux, both are what an administrator would use by hand, and
// neither needs a dependency.
func installTrust(caPath string) error {
	switch runtime.GOOS {
	case "windows":
		return installTrustWindows(caPath)
	case "linux":
		return installTrustLinux(caPath)
	default:
		return fmt.Errorf("installation automatique non prise en charge sur %s - "+
			"installe %s manuellement dans les autorités de confiance", runtime.GOOS, caPath)
	}
}

func installTrustWindows(caPath string) error {
	cmd := exec.Command("certutil", "-addstore", "-f", "Root", caPath)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		// The overwhelmingly likely cause is a non-elevated prompt, and the
		// raw certutil output does not say so clearly.
		return fmt.Errorf("installation refusée : %w\n"+
			"        Ouvre une invite de commande en tant qu'administrateur et relance :\n"+
			"          synsec cert trust\n\n"+
			"        Détail : %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}

func installTrustLinux(caPath string) error {
	const target = "/usr/local/share/ca-certificates/synsec.crt"

	source, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("lecture de %s : %w", caPath, err)
	}
	if err := os.WriteFile(target, source, 0o644); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("installation refusée : relance avec sudo\n" +
				"          sudo synsec cert trust")
		}
		return fmt.Errorf("écriture de %s : %w", target, err)
	}

	cmd := exec.Command("update-ca-certificates")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("update-ca-certificates : %w\n        Détail : %s",
			err, strings.TrimSpace(out.String()))
	}
	return nil
}
