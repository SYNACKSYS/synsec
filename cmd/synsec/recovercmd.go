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

// runRecover reopens a vault with the printed recovery code and re-seals it to
// this host.
//
// This is the path back from every situation where the machine keystore can no
// longer open the vault: Windows reinstalled, disk moved to another machine,
// service account changed, or - as here - the sealing scope deliberately
// changed. Without it the recovery code would be a promise SYNSEC could not
// keep.
func runRecover(args []string) error {
	cfg := config.Default()

	fs := flag.NewFlagSet("recover", flag.ExitOnError)
	fs.StringVar(&cfg.DataDir, "data", cfg.DataDir, "dossier de données")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec recover - rouvre le coffre avec le code de récupération

À utiliser quand SYNSEC ne parvient plus à ouvrir ses secrets tout seul :
Windows réinstallé, disque déplacé, ou compte de service modifié.

Le code de récupération est celui imprimé lors de « synsec init ».

Options :
`)+"\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(permute(fs, args)); err != nil {
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
	ctx := context.Background()

	ready, err := manager.Initialized(ctx)
	if err != nil {
		return err
	}
	if !ready {
		return errors.New("ce serveur n'est pas encore préparé - lance : synsec init")
	}

	code, err := promptPassword("Code de récupération : ")
	if err != nil {
		return err
	}

	if err := manager.UnsealWithRecovery(ctx, code); err != nil {
		if errors.Is(err, vault.ErrBadRecoveryCode) {
			return errors.New("ce code ne correspond pas.\n" +
				"        Vérifie la feuille imprimée à l'installation ; les tirets,\n" +
				"        les espaces et la casse n'ont aucune importance")
		}
		return err
	}
	defer manager.Seal()

	provider, err := manager.ReprovisionMachineSlot(ctx)
	if err != nil {
		return fmt.Errorf("le coffre s'est ouvert, mais n'a pas pu être re-scellé à cette machine : %w", err)
	}

	fmt.Println()
	fmt.Println("Coffre rouvert et re-scellé à cette machine.")
	fmt.Printf("Protection : %s\n", provider.Name())
	fmt.Printf("  %s\n", wrap(provider.Protection().Summary, 66, "  "))
	fmt.Println()
	fmt.Println("SYNSEC redémarrera de nouveau tout seul. Conserve le code de")
	fmt.Println("récupération : il reste valable et servira à la prochaine panne.")
	return nil
}
