package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"synsec/internal/store"
	"synsec/internal/vault"
)

func runSecret(args []string) error {
	if len(args) == 0 {
		return usageSecret()
	}

	switch args[0] {
	case "set", "put":
		return runSecretSet(args[1:])
	case "get":
		return runSecretGet(args[1:])
	case "list", "ls":
		return runSecretList(args[1:])
	case "rm", "delete":
		return runSecretRemove(args[1:])
	case "versions", "historique":
		return runSecretVersions(args[1:])
	case "revenir", "revert":
		return runSecretRevert(args[1:])
	case "reseau", "réseau", "network":
		return runSecretNetwork(args[1:])
	case "partager", "share":
		return runSecretShare(args[1:])
	case "partages", "shares":
		return runSecretShares(args[1:])
	case "retirer", "unshare":
		return runSecretUnshare(args[1:])
	case "-h", "--help", "help":
		return usageSecret()
	default:
		return fmt.Errorf("sous-commande inconnue : secret %q", args[0])
	}
}

func usageSecret() error {
	fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec secret - gère les secrets d'un coffre

  synsec secret set  <coffre> <nom> [-value "..."]
  synsec secret get  <coffre> <nom>
  synsec secret list <coffre>
  synsec secret rm   <coffre> <nom>

  synsec secret versions <coffre> <nom>
  synsec secret revenir  <coffre> <nom> <version>

  synsec secret partager <coffre> <nom> <utilisateur> [-role lecture|écriture] -user <nom>
  synsec secret partages <coffre> <nom>
  synsec secret retirer  <coffre> <nom> <utilisateur>

  synsec secret reseau   <list|add|rm> ...   restreint un secret à des adresses

Ces commandes demandent le mot de passe de ton compte et appliquent les mêmes
droits que l'interface web. Indique le compte avec -user, ou pose la variable
SYNSEC_USER une fois pour la session.

Sans -value, la valeur est lue sur l'entrée standard : elle n'apparaît alors
ni dans l'historique du shell ni dans la liste des processus.

Partager un secret ne donne accès qu'à celui-là : le reste du coffre demeure
invisible pour la personne à qui tu le confies.
`)+"\n")
	return nil
}

func runSecretSet(args []string) error {
	fs := flag.NewFlagSet("secret set", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	value := fs.String("value", "", "valeur du secret (à éviter : reste dans l'historique)")
	label := fs.String("label", "", "libellé lisible, à la création (défaut : le nom)")
	env := fs.String("env", store.DefaultEnvironment, "environnement")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage : synsec secret set <coffre> <nom>")
	}

	valueSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "value" {
			valueSet = true
		}
	})

	return withManager(*dataDir, func(ctx context.Context, m *vault.Manager) error {
		p, err := resolveVault(ctx, m.DB(), fs.Arg(0))
		if err != nil {
			return err
		}
		user, err := authenticate(ctx, m.DB(), *who)
		if err != nil {
			return err
		}

		// After the identity, never before: both read standard input, and the
		// value takes everything that is left.
		plain, err := readValue(*value, valueSet)
		if err != nil {
			return err
		}

		// Rewriting an existing secret may rest on an individual share;
		// creating one is a right over the vault.
		loc := store.SecretLocation{ProjectID: p.ID, Env: *env, Name: fs.Arg(1)}
		if _, err := m.DB().SecretMeta(ctx, loc); err == nil {
			if _, err := requireSecretRole(ctx, m.DB(), user, p, *env, fs.Arg(1), store.RoleWriter); err != nil {
				return err
			}
		} else if errors.Is(err, store.ErrNotFound) {
			if err := requireVaultRole(ctx, m.DB(), user, p, store.RoleWriter); err != nil {
				return err
			}
		} else {
			return err
		}

		sec, err := m.PutSecret(ctx, loc, plain, *label, user.Username)
		if err != nil {
			return err
		}

		auditCLI(ctx, m.DB(), user, "secret.write", sec.Name)
		fmt.Printf("%s enregistré dans « %s » (version %d).\n", sec.Name, p.Name, sec.CurrentVersion)
		return nil
	})
}

func runSecretGet(args []string) error {
	fs := flag.NewFlagSet("secret get", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	env := fs.String("env", store.DefaultEnvironment, "environnement")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage : synsec secret get <coffre> <nom>")
	}

	return withManager(*dataDir, func(ctx context.Context, m *vault.Manager) error {
		p, err := resolveVault(ctx, m.DB(), fs.Arg(0))
		if err != nil {
			return err
		}
		user, err := authenticate(ctx, m.DB(), *who)
		if err != nil {
			return err
		}
		if _, err := requireSecretRole(ctx, m.DB(), user, p, *env, fs.Arg(1), store.RoleReader); err != nil {
			return err
		}

		loc := store.SecretLocation{ProjectID: p.ID, Env: *env, Name: fs.Arg(1)}
		value, err := m.GetSecret(ctx, loc)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("aucun secret nommé %s dans « %s »", fs.Arg(1), p.Name)
		}
		if err != nil {
			return err
		}
		auditCLI(ctx, m.DB(), user, "secret.read", fs.Arg(1))

		// Written raw, with no trailing newline, so the output can be piped
		// into another command without picking up a stray byte.
		os.Stdout.Write(value)
		return nil
	})
}

func runSecretList(args []string) error {
	fs := flag.NewFlagSet("secret list", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	env := fs.String("env", store.DefaultEnvironment, "environnement")

	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage : synsec secret list <coffre>")
	}

	// Listing touches no value, so the root key stays where it is.
	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		p, err := resolveVault(ctx, db, fs.Arg(0))
		if err != nil {
			return err
		}
		user, err := authenticate(ctx, db, *who)
		if err != nil {
			return err
		}
		if err := requireVaultRole(ctx, db, user, p, store.RoleReader); err != nil {
			return err
		}

		secrets, err := db.ListSecrets(ctx, p.ID, *env)
		if err != nil {
			return err
		}
		if len(secrets) == 0 {
			fmt.Printf("Aucun secret dans « %s ».\n", p.Name)
			return nil
		}

		// Values are never printed here: listing is something you do to find
		// your way around, not to read secrets.
		w := newTabWriter()
		fmt.Fprintln(w, "NOM\tVERSION\tMODIFIÉ LE")
		for _, s := range secrets {
			fmt.Fprintf(w, "%s\t%d\t%s\n", s.Name, s.CurrentVersion, formatTime(s.UpdatedAt))
		}
		return w.Flush()
	})
}

func runSecretRemove(args []string) error {
	fs := flag.NewFlagSet("secret rm", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	env := fs.String("env", store.DefaultEnvironment, "environnement")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage : synsec secret rm <coffre> <nom>")
	}

	// Deleting a ciphertext does not require being able to read it.
	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		p, err := resolveVault(ctx, db, fs.Arg(0))
		if err != nil {
			return err
		}
		user, err := authenticate(ctx, db, *who)
		if err != nil {
			return err
		}
		// Destroying a secret and its history is a right over the vault: an
		// individual share never grants it, here as in the interface.
		if err := requireVaultRole(ctx, db, user, p, store.RoleWriter); err != nil {
			return err
		}

		loc := store.SecretLocation{ProjectID: p.ID, Env: *env, Name: fs.Arg(1)}
		if err := db.DeleteSecret(ctx, loc); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("aucun secret nommé %s dans « %s »", fs.Arg(1), p.Name)
			}
			return err
		}

		auditCLI(ctx, db, user, "secret.delete", fs.Arg(1))
		fmt.Printf("%s supprimé de « %s », avec tout son historique.\n", fs.Arg(1), p.Name)
		return nil
	})
}

// runSecretVersions lists a secret's history.
//
// Metadata only: no version is decrypted. Listing the past must not amount to
// reading it, and a command that opened every value to print a table would say
// exactly that in the audit log.
func runSecretVersions(args []string) error {
	fs := flag.NewFlagSet("secret versions", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	env := fs.String("env", store.DefaultEnvironment, "environnement")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage : synsec secret versions <coffre> <nom>")
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		p, err := resolveVault(ctx, db, fs.Arg(0))
		if err != nil {
			return err
		}
		user, err := authenticate(ctx, db, *who)
		if err != nil {
			return err
		}
		secret, err := requireSecretRole(ctx, db, user, p, *env, fs.Arg(1), store.RoleReader)
		if err != nil {
			return err
		}

		versions, err := db.ListVersions(ctx, secret.ID)
		if err != nil {
			return err
		}

		w := newTabWriter()
		fmt.Fprintln(w, "VERSION\tENREGISTRÉE LE\tPAR\t")
		for _, v := range versions {
			current := ""
			if v.Version == secret.CurrentVersion {
				current = "en cours"
			}
			fmt.Fprintf(w, "v%d\t%s\t%s\t%s\n",
				v.Version, formatTime(v.CreatedAt), v.CreatedBy, current)
		}
		return w.Flush()
	})
}

// runSecretRevert brings an old value back as a new version.
func runSecretRevert(args []string) error {
	fs := flag.NewFlagSet("secret revenir", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	env := fs.String("env", store.DefaultEnvironment, "environnement")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 3 {
		return errors.New("usage : synsec secret revenir <coffre> <nom> <version>")
	}

	version, err := strconv.ParseInt(fs.Arg(2), 10, 64)
	if err != nil {
		return fmt.Errorf("« %s » n'est pas un numéro de version", fs.Arg(2))
	}

	return withManager(*dataDir, func(ctx context.Context, m *vault.Manager) error {
		p, err := resolveVault(ctx, m.DB(), fs.Arg(0))
		if err != nil {
			return err
		}
		user, err := authenticate(ctx, m.DB(), *who)
		if err != nil {
			return err
		}
		if _, err := requireSecretRole(ctx, m.DB(), user, p, *env, fs.Arg(1), store.RoleWriter); err != nil {
			return err
		}

		loc := store.SecretLocation{ProjectID: p.ID, Env: *env, Name: fs.Arg(1)}
		restored, err := m.RevertSecret(ctx, loc, version, user.Username)
		if err != nil {
			return err
		}

		auditCLI(ctx, m.DB(), user, "secret.revert", fs.Arg(1))
		fmt.Printf("Valeur de la version %d rétablie, enregistrée en version %d.\n",
			version, restored.CurrentVersion)
		fmt.Println("L'historique est intact : rien n'a été effacé.")
		return nil
	})
}
