package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"synsec/internal/config"
)

// serviceName is what the platform's service manager knows SYNSEC by.
const serviceName = "SYNSEC"

func runService(args []string) error {
	if len(args) == 0 {
		return usageService()
	}

	switch args[0] {
	case "install", "installer":
		return runServiceInstall(args[1:])
	case "uninstall", "remove", "desinstaller":
		return runServiceUninstall(args[1:])
	case "status", "etat":
		return runServiceStatus(args[1:])
	case "-h", "--help", "help":
		return usageService()
	default:
		return fmt.Errorf("sous-commande inconnue : service %q", args[0])
	}
}

func usageService() error {
	fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec service - démarrage automatique

  synsec service install [options de serve]
  synsec service uninstall
  synsec service status

Le service sert exclusivement en HTTPS. Il n'existe aucun mode HTTP.

Les options acceptées sont celles de « synsec serve » : elles sont inscrites
dans la définition du service et reprises à chaque démarrage. Pour les changer
ensuite, réinstalle le service avec les nouvelles.

Installe SYNSEC comme service système : il démarrera tout seul avec la
machine, avant même qu'un utilisateur ouvre une session, et redémarrera de
lui-même après une panne.

À lancer en administrateur (Windows) ou avec sudo (Linux).
`)+"\n")
	return nil
}

func runServiceInstall(args []string) error {
	cfg := config.Default()

	fs := flag.NewFlagSet("service install", flag.ExitOnError)
	// The same options as `serve`, and they are written into the service
	// definition: a server installed with a policy has to come back with it
	// after a reboot.
	apply := serveOptions(fs, &cfg)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	apply()

	// The data directory is resolved to an absolute path before it is baked
	// into the service definition: a service starts with a working directory
	// nobody chose, so a relative path would point somewhere unexpected - and
	// the failure would surface as an empty server rather than an error.
	absolute, err := absolutePath(cfg.DataDir)
	if err != nil {
		return err
	}
	cfg.DataDir = absolute

	if err := cfg.Prepare(); err != nil {
		return err
	}
	if err := installService(cfg); err != nil {
		return err
	}

	fmt.Printf("Service %s installé et démarré.\n", serviceName)
	fmt.Printf("Dossier de données : %s\n", cfg.DataDir)
	if extra := serveArgs(cfg); len(extra) > 4 {
		fmt.Printf("Options enregistrées : %s\n", strings.Join(extra[5:], " "))
	}
	fmt.Println()
	fmt.Println("Il redémarrera automatiquement avec la machine.")
	fmt.Println("Pour vérifier :  synsec service status")
	return nil
}

func runServiceUninstall(args []string) error {
	fs := flag.NewFlagSet("service uninstall", flag.ExitOnError)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}

	if err := uninstallService(); err != nil {
		return err
	}

	fmt.Printf("Service %s arrêté et supprimé.\n", serviceName)
	fmt.Println("Tes coffres et tes secrets sont intacts : seul le service a été retiré.")
	return nil
}

func runServiceStatus(args []string) error {
	fs := flag.NewFlagSet("service status", flag.ExitOnError)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}

	status, err := serviceStatus()
	if err != nil {
		return err
	}
	fmt.Println(status)
	return nil
}

func absolutePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("aucun dossier de données")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("chemin %s : %w", path, err)
	}
	return abs, nil
}
