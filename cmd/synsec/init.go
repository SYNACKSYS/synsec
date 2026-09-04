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
	sansElevation := fs.Bool("sans-elevation", false,
		"installer sans droits administrateur, sans la puce TPM")
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

	// Avant d'ouvrir la base : dire sous quelle protection on va travailler,
	// et refuser si la fenêtre ne permet pas d'obtenir celle que la machine
	// offre. Rien n'est créé tant que ça n'a pas été annoncé.
	if err := preflight(cfg.DataDir, *sansElevation); err != nil {
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
	warnIfWeakerThanPossible(manager, res.Provider)
	return nil
}

// warnIfWeakerThanPossible est le filet, pas l'annonce.
//
// L'annonce se fait avant l'installation, dans preflight. Ceci rattrape le cas
// où le scellement retenu échoue en cours de route et où le repli s'applique :
// on a alors obtenu autre chose que ce qui venait d'être promis, et se taire
// serait pire que tout.
func warnIfWeakerThanPossible(m *vault.Manager, obtenu string) {
	meilleur := m.BestProvider()
	if meilleur.Name() == obtenu {
		return
	}

	line := strings.Repeat("=", 66)
	fmt.Println(line)
	fmt.Println()
	fmt.Println("  ATTENTION : protection plus faible que possible")
	fmt.Println()
	fmt.Printf("  Obtenue     : %s\n", providerLabel(obtenu))
	fmt.Printf("  Disponible  : %s\n", providerLabel(meilleur.Name()))
	fmt.Println()
	if hint := elevationHint(); hint != "" {
		fmt.Printf("  %s\n", wrap(hint, 64, "  "))
		fmt.Println()
	}
	fmt.Println("  Une fois le problème réglé, sans tout réinstaller :")
	fmt.Println()
	fmt.Println("    synsec maintenance sceller -user <nom>")
	fmt.Println()
	fmt.Println(line)
	fmt.Println()
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
	fmt.Println("  réinstalles le système, ou si le compte de service change.")
	fmt.Println()
	fmt.Println("  Range-le ailleurs que sur ce serveur. Une feuille de papier")
	fmt.Println("  dans un tiroir fait très bien l'affaire.")
	fmt.Println()
	fmt.Println(line)
	fmt.Println()

	fmt.Printf("  Protection de la clé : %s\n", providerLabel(res.Provider))
	fmt.Printf("  %s\n", wrap(res.Protection.Summary, 64, "  "))
	if res.Protection.Caveat != "" {
		fmt.Println()
		// L'étiquette sur sa propre ligne : mise devant le texte, elle mangeait
		// quatorze colonnes de la première ligne seulement, qui débordait alors
		// que les suivantes tombaient juste.
		if res.Protection.ResistsDiskTheft {
			fmt.Println("  À savoir :")
		} else {
			fmt.Println("  ATTENTION :")
		}
		fmt.Printf("  %s\n", wrap(res.Protection.Caveat, 64, "  "))
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
