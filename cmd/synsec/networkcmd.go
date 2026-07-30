package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"synsec/internal/store"
)

func runSecretNetwork(args []string) error {
	if len(args) == 0 {
		return usageSecretNetwork()
	}

	switch args[0] {
	case "list", "ls":
		return runNetworkList(args[1:])
	case "add", "ajouter":
		return runNetworkAdd(args[1:])
	case "rm", "retirer":
		return runNetworkRemove(args[1:])
	case "-h", "--help", "help":
		return usageSecretNetwork()
	default:
		return fmt.Errorf("sous-commande inconnue : secret reseau %q", args[0])
	}
}

func usageSecretNetwork() error {
	fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec secret reseau - restreint un secret à certaines adresses

  synsec secret reseau list <coffre> <chemin>
  synsec secret reseau add  <coffre> <chemin> <adresse|bloc CIDR>
  synsec secret reseau rm   <coffre> <chemin> <adresse|bloc CIDR>

Sans aucune adresse, le secret est lisible depuis partout - c'est le défaut.
Dès qu'une adresse est ajoutée, il n'est plus lisible que depuis celles-là,
quel que soit le token utilisé, y compris depuis le navigateur et depuis la
console du serveur. Pense à ajouter 127.0.0.1 si tu veux garder l'accès local.

Gérer cette liste demande la gestion du coffre : personne ne peut s'enfermer
dehors, un gestionnaire retire toujours une restriction depuis n'importe où.

Exemples :
  synsec secret reseau add Maison /zigbee/cle 192.168.1.72
  synsec secret reseau add Maison /zigbee/cle 192.168.1.0/24
`)+"\n")
	return nil
}

func runNetworkList(args []string) error {
	fs := flag.NewFlagSet("secret reseau list", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	env := fs.String("env", store.DefaultEnvironment, "environnement")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage : synsec secret reseau list <coffre> <nom>")
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		secret, _, err := manageableSecret(ctx, db, *who, fs.Arg(0), *env, fs.Arg(1))
		if err != nil {
			return err
		}

		networks, err := db.ListSecretNetworks(ctx, secret.ID)
		if err != nil {
			return err
		}
		if len(networks) == 0 {
			fmt.Printf("%s est lisible depuis n'importe quelle adresse.\n", secret.Name)
			return nil
		}

		fmt.Printf("%s n'est lisible que depuis :\n\n", secret.Name)
		w := newTabWriter()
		fmt.Fprintln(w, "ADRESSE\tAJOUTÉE LE\tPAR")
		for _, n := range networks {
			fmt.Fprintf(w, "%s\t%s\t%s\n", n.Network, formatTime(n.AddedAt), n.AddedBy)
		}
		return w.Flush()
	})
}

func runNetworkAdd(args []string) error {
	fs := flag.NewFlagSet("secret reseau add", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	env := fs.String("env", store.DefaultEnvironment, "environnement")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 3 {
		return errors.New("usage : synsec secret reseau add <coffre> <chemin> <adresse>")
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		secret, user, err := manageableSecret(ctx, db, *who, fs.Arg(0), *env, fs.Arg(1))
		if err != nil {
			return err
		}

		existing, err := db.ListSecretNetworks(ctx, secret.ID)
		if err != nil {
			return err
		}

		if err := db.AddSecretNetwork(ctx, secret.ID, fs.Arg(2), user.Username); err != nil {
			return err
		}
		auditCLI(ctx, db, user, secret.ProjectID, "secret.pin", secret.Name)

		network, _ := store.ParseNetwork(fs.Arg(2))
		fmt.Printf("%s : accès autorisé depuis %s.\n", secret.Name, network)

		// The first entry is the one that changes the behaviour, from "anywhere"
		// to "only here". Saying so avoids the surprise of a device that stops
		// working for reasons nobody connects to this command.
		if len(existing) == 0 {
			fmt.Println()
			fmt.Println("C'est la première restriction sur ce secret : il n'est désormais")
			fmt.Println("plus lisible depuis aucune autre adresse, ni par un appareil, ni")
			fmt.Println("depuis le navigateur, ni depuis ce serveur.")
		}
		return nil
	})
}

func runNetworkRemove(args []string) error {
	fs := flag.NewFlagSet("secret reseau rm", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	env := fs.String("env", store.DefaultEnvironment, "environnement")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 3 {
		return errors.New("usage : synsec secret reseau rm <coffre> <chemin> <adresse>")
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		secret, user, err := manageableSecret(ctx, db, *who, fs.Arg(0), *env, fs.Arg(1))
		if err != nil {
			return err
		}

		if err := db.RemoveSecretNetwork(ctx, secret.ID, fs.Arg(2)); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("%s n'était pas restreint à %s", secret.Name, fs.Arg(2))
			}
			return err
		}
		auditCLI(ctx, db, user, secret.ProjectID, "secret.unpin", secret.Name)

		remaining, err := db.ListSecretNetworks(ctx, secret.ID)
		if err != nil {
			return err
		}
		if len(remaining) == 0 {
			fmt.Printf("%s est de nouveau lisible depuis n'importe quelle adresse.\n", secret.Name)
		} else {
			fmt.Printf("%s : restriction retirée, %d adresse(s) restante(s).\n", secret.Name, len(remaining))
		}
		return nil
	})
}

// manageableSecret authenticates, resolves the secret, and checks the caller
// manages the vault it belongs to.
//
// Managing restrictions is a manager's right rather than a writer's: it decides
// who may read, which is the same kind of decision as handing out access.
func manageableSecret(ctx context.Context, db *store.DB, who, vaultRef, env, path string) (store.Secret, store.User, error) {
	p, err := resolveVault(ctx, db, vaultRef)
	if err != nil {
		return store.Secret{}, store.User{}, err
	}
	user, err := authenticate(ctx, db, who)
	if err != nil {
		return store.Secret{}, store.User{}, err
	}
	if err := requireVaultRole(ctx, db, user, p, store.RoleManager); err != nil {
		return store.Secret{}, store.User{}, err
	}

	loc := store.SecretLocation{ProjectID: p.ID, Env: env, Name: path}
	secret, err := db.SecretMeta(ctx, loc)
	if errors.Is(err, store.ErrNotFound) {
		return store.Secret{}, store.User{}, fmt.Errorf("aucun secret nommé %s dans « %s »", path, p.Name)
	}
	if err != nil {
		return store.Secret{}, store.User{}, err
	}
	return secret, user, nil
}
