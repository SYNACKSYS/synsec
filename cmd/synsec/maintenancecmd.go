package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"synsec/internal/config"
	"synsec/internal/store"
)

func runMaintenance(args []string) error {
	if len(args) == 0 {
		return usageMaintenance()
	}

	switch args[0] {
	case "nettoyer", "vacuum":
		return runMaintenanceVacuum(args[1:])
	case "sceller", "reseal":
		return runMaintenanceReseal(args[1:])
	case "-h", "--help", "help":
		return usageMaintenance()
	default:
		return fmt.Errorf("sous-commande inconnue : maintenance %q", args[0])
	}
}

func usageMaintenance() error {
	fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec maintenance - entretien de la base

  synsec maintenance nettoyer
  synsec maintenance sceller

« sceller » remet la clé racine sous la meilleure protection que cette machine
sache offrir aujourd'hui. Utile après avoir activé le TPM dans le firmware :
une installation garde la protection choisie le jour de sa mise en place, et
ne change jamais toute seule.

« nettoyer » réécrit la base pour effacer les pages libérées par les suppressions
antérieures, et vérifie son intégrité au passage.

Depuis la version qui a introduit cette commande, une suppression écrase déjà
ce qu'elle libère. Ce nettoyage sert pour ce qui a été supprimé avant : un
secret effacé, un coffre supprimé ou une rotation de clé faite à l'époque
laissaient leur contenu chiffré dans le fichier, lisible avec la clé du coffre.

Le serveur doit être arrêté : la réécriture demande un accès exclusif.
`)+"\n")
	return nil
}

// runMaintenanceVacuum rewrites the database file.
//
// Three steps, in this order. The write-ahead log is folded in and truncated
// first, because deleted rows sitting there would survive a rewrite of the
// main file alone. Then the rewrite itself, which is what drops the free pages
// rather than merely marking them reusable. Then the log is truncated again,
// since the rewrite is itself a large transaction that fills it.
func runMaintenanceVacuum(args []string) error {
	fs := flag.NewFlagSet("maintenance nettoyer", flag.ExitOnError)
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

	path := cfg.DatabasePath()
	before := fileSize(path) + fileSize(path+"-wal")

	db, err := store.Open(path)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()

	fmt.Println("Vérification de l'intégrité...")
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return fmt.Errorf("vérification de l'intégrité : %w", err)
	}
	if integrity != "ok" {
		return fmt.Errorf("la base signale un problème d'intégrité : %s\n"+
			"        Ne la réécris pas : restaure une sauvegarde", integrity)
	}
	fmt.Println("  intégrité : ok")

	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return busyOrError(err)
	}

	fmt.Println("Réécriture de la base...")
	if _, err := db.ExecContext(ctx, `VACUUM`); err != nil {
		return busyOrError(err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return busyOrError(err)
	}

	after := fileSize(path) + fileSize(path+"-wal")
	fmt.Printf("Fait. %s avant, %s après.\n", humanBytes(before), humanBytes(after))
	fmt.Println()
	fmt.Println("Les pages libérées par les suppressions passées ne contiennent plus rien.")
	fmt.Println("Ce que le système de fichiers ou le disque conserve de l'ancien fichier")
	fmt.Println("échappe en revanche à SYNSEC : sur un SSD, seul le chiffrement du disque")
	fmt.Println("répond à cette question.")
	return nil
}

// busyOrError turns the one failure an operator will actually hit into an
// instruction rather than a database error.
func busyOrError(err error) error {
	if strings.Contains(strings.ToLower(err.Error()), "locked") ||
		strings.Contains(strings.ToLower(err.Error()), "busy") {
		return fmt.Errorf("la base est utilisée par le serveur\n" +
			"        Arrête-le d'abord :  net stop SYNSEC   (ou : sudo systemctl stop synsec)")
	}
	return err
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f Mio", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f Kio", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d octets", n)
	}
}
