package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"synsec/internal/store"
	"synsec/internal/vault"
)

func runVault(args []string) error {
	if len(args) == 0 {
		return usageVault()
	}

	switch args[0] {
	case "list", "ls":
		return runVaultList(args[1:])
	case "create", "new":
		return runVaultCreate(args[1:])
	case "partager", "share":
		return runVaultShare(args[1:])
	case "membres", "members":
		return runVaultMembers(args[1:])
	case "retirer", "unshare":
		return runVaultUnshare(args[1:])
	case "supprimer", "rm", "delete":
		return runVaultDelete(args[1:])
	case "-h", "--help", "help":
		return usageVault()
	default:
		return fmt.Errorf("sous-commande inconnue : coffre %q", args[0])
	}
}

func usageVault() error {
	fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec coffre - gère les coffres

  synsec coffre list
  synsec coffre create    <nom> [-description "..."]
  synsec coffre supprimer <coffre> -confirmer <nom>

  synsec coffre partager  <coffre> <utilisateur> [-role lecture|écriture|gestion]
  synsec coffre membres   <coffre>
  synsec coffre retirer   <coffre> <utilisateur>

Un coffre est invisible pour qui n'y a pas accès - il n'apparaît pas dans son
interface. Pour ne confier qu'un seul secret, voir « synsec secret partager ».

Supprimer un coffre emporte ses secrets, leur historique et ses appareils. Il
n'y a pas de corbeille : seule une sauvegarde antérieure les ramène.
`)+"\n")
	return nil
}

func runVaultCreate(args []string) error {
	fs := flag.NewFlagSet("coffre create", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	description := fs.String("description", "", "description du coffre")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage : synsec coffre create <nom>")
	}
	name := fs.Arg(0)

	return withManager(*dataDir, func(ctx context.Context, m *vault.Manager) error {
		user, err := authenticate(ctx, m.DB(), *who)
		if err != nil {
			return err
		}

		p, err := m.CreateVault(ctx, name, *description, user.ID)
		if err != nil {
			return err
		}

		// Without this the vault would belong to nobody, and since an
		// administrator no longer sees what was not shared with them, it would
		// be invisible in the interface to every account on the server.
		if err := m.DB().SetVaultMember(ctx, p.ID, user.ID, store.RoleManager, user.Username); err != nil {
			return err
		}

		auditCLI(ctx, m.DB(), user, "vault.create", p.Name)
		fmt.Printf("Coffre « %s » créé, géré par « %s ».\n", p.Name, user.Username)
		fmt.Printf("Identifiant : %s\n", p.ID)
		return nil
	})
}

// runVaultDelete destroys a vault and everything in it.
func runVaultDelete(args []string) error {
	fs := flag.NewFlagSet("coffre supprimer", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	confirm := fs.String("confirmer", "", "recopier le nom du coffre pour confirmer")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage : synsec coffre supprimer <coffre> -confirmer <nom>")
	}

	return withManager(*dataDir, func(ctx context.Context, m *vault.Manager) error {
		user, err := authenticate(ctx, m.DB(), *who)
		if err != nil {
			return err
		}
		p, err := resolveVault(ctx, m.DB(), fs.Arg(0))
		if err != nil {
			return err
		}
		if err := requireVaultRole(ctx, m.DB(), user, p, store.RoleManager); err != nil {
			return err
		}

		// The owner alone, matching the interface. Managing a vault means
		// deciding who gets in; destroying it takes everyone's secrets with it.
		// A vault whose owner's account is gone falls back to its managers,
		// otherwise it could never be removed.
		if p.OwnerID != "" && p.OwnerID != user.ID {
			return fmt.Errorf("« %s » appartient à quelqu'un d'autre : seul son propriétaire peut le supprimer", p.Name)
		}

		// The name typed out, like the interface asks for. Nobody writes a
		// vault's name by accident, and this is the one command no backup
		// taken afterwards can undo.
		if strings.TrimSpace(*confirm) != p.Name {
			return fmt.Errorf("pour confirmer, ajoute : -confirmer %q", p.Name)
		}

		secrets, err := m.DB().ListSecrets(ctx, p.ID, store.DefaultEnvironment)
		if err != nil {
			return err
		}
		if err := m.DB().DeleteProject(ctx, p.ID); err != nil {
			return err
		}

		auditCLI(ctx, m.DB(), user, "vault.delete", p.Name)
		fmt.Printf("Coffre « %s » supprimé, avec %d secret(s) et leurs appareils.\n",
			p.Name, len(secrets))
		return nil
	})
}

func runVaultList(args []string) error {
	fs := flag.NewFlagSet("coffre list", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		vaults, err := db.ListProjects(ctx)
		if err != nil {
			return err
		}
		if len(vaults) == 0 {
			fmt.Println("Aucun coffre. Crée le premier avec : synsec coffre create Maison")
			return nil
		}

		w := newTabWriter()
		fmt.Fprintln(w, "NOM\tIDENTIFIANT\tSECRETS\tCRÉÉ LE")
		for _, p := range vaults {
			secrets, err := db.ListSecrets(ctx, p.ID, store.DefaultEnvironment)
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", p.Name, p.ID, len(secrets), formatTime(p.CreatedAt))
		}
		return w.Flush()
	})
}
