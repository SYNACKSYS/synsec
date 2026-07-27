package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"synsec/internal/config"
	"synsec/internal/store"
	"synsec/internal/vault"
)

func runInit(args []string) error {
	cfg := config.Default()

	fs := flag.NewFlagSet("init", flag.ExitOnError)
	fs.StringVar(&cfg.DataDir, "data", cfg.DataDir, "dossier de données")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec init - prépare le serveur

Crée la clé de chiffrement, la scelle à cette machine et imprime le code de
récupération. À exécuter une seule fois, avant le premier démarrage.

Options :
`)+"\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := cfg.Prepare(); err != nil {
		return err
	}

	db, err := store.Open(cfg.DatabasePath())
	if err != nil {
		return err
	}
	defer db.Close()

	manager := vault.New(db, cfg.DataDir)
	res, err := manager.Initialize(context.Background())
	if errors.Is(err, vault.ErrAlreadyInitialized) {
		return fmt.Errorf("ce serveur est déjà préparé (%s)\n"+
			"        Pour repartir de zéro, supprime le dossier de données - "+
			"tous les secrets seront perdus", cfg.DataDir)
	}
	if err != nil {
		return err
	}
	defer manager.Seal()

	printRecoveryKit(cfg, res)
	return nil
}

// printRecoveryKit is the one moment the recovery code is ever shown.
//
// It is printed loudly and at length on purpose. The most likely way a
// household loses every secret it owns is not an attacker - it is a dead
// machine and a recovery code nobody wrote down.
func printRecoveryKit(cfg config.Config, res vault.InitResult) {
	line := strings.Repeat("=", 66)

	fmt.Println()
	fmt.Println(line)
	fmt.Println("  SYNSEC est prêt.")
	fmt.Println(line)
	fmt.Println()
	fmt.Println("  CODE DE RÉCUPÉRATION - À IMPRIMER MAINTENANT")
	fmt.Println()
	fmt.Printf("      %s\n", res.RecoveryCode)
	fmt.Println()
	fmt.Println("  Ce code ne sera plus jamais affiché. Il est la seule façon de")
	fmt.Println("  rouvrir tes secrets si cette machine tombe en panne, si tu")
	fmt.Println("  réinstalles Windows, ou si le compte de service change.")
	fmt.Println()
	fmt.Println("  Range-le ailleurs que sur ce serveur. Une feuille de papier")
	fmt.Println("  dans un tiroir fait très bien l'affaire.")
	fmt.Println()
	fmt.Println(line)
	fmt.Println()

	fmt.Printf("  Protection de la clé : %s\n", res.Provider)
	fmt.Printf("  %s\n", wrap(res.Protection.Summary, 64, "  "))
	if res.Protection.Caveat != "" {
		fmt.Println()
		if res.Protection.ResistsDiskTheft {
			fmt.Printf("  À savoir : %s\n", wrap(res.Protection.Caveat, 64, "  "))
		} else {
			fmt.Printf("  ATTENTION : %s\n", wrap(res.Protection.Caveat, 64, "  "))
		}
	}

	fmt.Println()
	fmt.Printf("  Dossier de données : %s\n", cfg.DataDir)
	fmt.Println()
	fmt.Println("  Démarre le serveur avec :  synsec serve")
	fmt.Println()
}

// wrap breaks a line at word boundaries so a terminal window of ordinary width
// does not scramble the warning that matters most.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}

	var b strings.Builder
	lineLen := 0
	for i, w := range words {
		switch {
		case i == 0:
			b.WriteString(w)
			lineLen = len(w)
		case lineLen+1+len(w) > width:
			b.WriteString("\n" + indent + w)
			lineLen = len(w)
		default:
			b.WriteString(" " + w)
			lineLen += 1 + len(w)
		}
	}
	return b.String()
}
