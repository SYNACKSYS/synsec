package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"synsec/internal/store"
)

// resolveUser looks an account up by name.
func resolveUser(ctx context.Context, db *store.DB, name string) (store.User, error) {
	u, err := db.UserByUsername(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return store.User{}, fmt.Errorf("aucun compte nommé %q", name)
	}
	return u, err
}

// parseRole turns what was typed into a role, accepting the French words the
// interface uses as well as the stored names.
func parseRole(raw string, allowManager bool) (store.Role, error) {
	switch raw {
	case "reader", "lecture", "lecteur":
		return store.RoleReader, nil
	case "writer", "ecriture", "écriture", "redacteur", "rédacteur":
		return store.RoleWriter, nil
	case "manager", "gestion", "gestionnaire":
		if !allowManager {
			return store.RoleNone, errors.New("un secret ne se partage qu'en lecture ou en écriture")
		}
		return store.RoleManager, nil
	default:
		if allowManager {
			return store.RoleNone, fmt.Errorf("rôle inconnu %q - lecture, écriture ou gestion", raw)
		}
		return store.RoleNone, fmt.Errorf("rôle inconnu %q - lecture ou écriture", raw)
	}
}

// runVaultShare grants someone access to a whole vault.
func runVaultShare(args []string) error {
	fs := flag.NewFlagSet("coffre partager", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	roleName := fs.String("role", "lecture", "lecture, écriture ou gestion")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage : synsec coffre partager <coffre> <utilisateur> [-role lecture]")
	}

	role, err := parseRole(*roleName, true)
	if err != nil {
		return err
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		p, err := resolveVault(ctx, db, fs.Arg(0))
		if err != nil {
			return err
		}
		u, err := resolveUser(ctx, db, fs.Arg(1))
		if err != nil {
			return err
		}

		if err := db.SetVaultMember(ctx, p.ID, u.ID, role, "cli"); err != nil {
			return err
		}
		fmt.Printf("« %s » a maintenant l'accès en %s au coffre « %s ».\n",
			u.Username, role.Label(), p.Name)
		return nil
	})
}

// runVaultMembers lists who may reach a vault.
func runVaultMembers(args []string) error {
	fs := flag.NewFlagSet("coffre membres", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage : synsec coffre membres <coffre>")
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		p, err := resolveVault(ctx, db, fs.Arg(0))
		if err != nil {
			return err
		}

		members, err := db.ListVaultMembers(ctx, p.ID)
		if err != nil {
			return err
		}
		if len(members) == 0 {
			fmt.Printf("Personne n'a accès à « %s » en dehors des administrateurs.\n", p.Name)
			return nil
		}

		w := newTabWriter()
		fmt.Fprintln(w, "UTILISATEUR\tACCÈS\tDEPUIS\tPAR")
		for _, member := range members {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				member.Username, member.Role.Label(), formatTime(member.GrantedAt), member.GrantedBy)
		}
		return w.Flush()
	})
}

// runVaultUnshare revokes someone's access to a vault.
func runVaultUnshare(args []string) error {
	fs := flag.NewFlagSet("coffre retirer", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage : synsec coffre retirer <coffre> <utilisateur>")
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		p, err := resolveVault(ctx, db, fs.Arg(0))
		if err != nil {
			return err
		}
		u, err := resolveUser(ctx, db, fs.Arg(1))
		if err != nil {
			return err
		}

		if err := db.RemoveVaultMember(ctx, p.ID, u.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("« %s » n'avait pas accès à « %s »", u.Username, p.Name)
			}
			return err
		}
		fmt.Printf("« %s » n'a plus accès au coffre « %s ».\n", u.Username, p.Name)
		return nil
	})
}

// runSecretShare hands one secret to one person, without opening the rest of
// the vault to them.
func runSecretShare(args []string) error {
	fs := flag.NewFlagSet("secret partager", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	env := fs.String("env", store.DefaultEnvironment, "environnement")
	roleName := fs.String("role", "lecture", "lecture ou écriture")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 3 {
		return errors.New("usage : synsec secret partager <coffre> <nom> <utilisateur> [-role lecture]")
	}

	role, err := parseRole(*roleName, false)
	if err != nil {
		return err
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		p, err := resolveVault(ctx, db, fs.Arg(0))
		if err != nil {
			return err
		}
		loc := store.SecretLocation{ProjectID: p.ID, Env: *env, Name: fs.Arg(1)}
		secret, err := db.SecretMeta(ctx, loc)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("aucun secret nommé %s dans « %s »", fs.Arg(1), p.Name)
		}
		if err != nil {
			return err
		}
		u, err := resolveUser(ctx, db, fs.Arg(2))
		if err != nil {
			return err
		}

		if err := db.SetSecretShare(ctx, secret.ID, u.ID, role, "cli"); err != nil {
			return err
		}
		fmt.Printf("%s partagé en %s avec « %s ».\n", secret.Name, role.Label(), u.Username)
		fmt.Println("Le reste du coffre lui reste inaccessible.")
		return nil
	})
}

// runSecretShares lists who a secret has been handed to.
func runSecretShares(args []string) error {
	fs := flag.NewFlagSet("secret partages", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	env := fs.String("env", store.DefaultEnvironment, "environnement")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage : synsec secret partages <coffre> <nom>")
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		p, err := resolveVault(ctx, db, fs.Arg(0))
		if err != nil {
			return err
		}
		loc := store.SecretLocation{ProjectID: p.ID, Env: *env, Name: fs.Arg(1)}
		secret, err := db.SecretMeta(ctx, loc)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("aucun secret nommé %s dans « %s »", fs.Arg(1), p.Name)
		}
		if err != nil {
			return err
		}

		shares, err := db.ListSecretShares(ctx, secret.ID)
		if err != nil {
			return err
		}
		if len(shares) == 0 {
			fmt.Printf("%s n'est partagé avec personne individuellement.\n", secret.Name)
			return nil
		}

		w := newTabWriter()
		fmt.Fprintln(w, "UTILISATEUR\tACCÈS\tDEPUIS\tPAR")
		for _, share := range shares {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				share.Username, share.Role.Label(), formatTime(share.GrantedAt), share.GrantedBy)
		}
		return w.Flush()
	})
}

// runSecretUnshare withdraws an individual share.
func runSecretUnshare(args []string) error {
	fs := flag.NewFlagSet("secret retirer", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	env := fs.String("env", store.DefaultEnvironment, "environnement")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 3 {
		return errors.New("usage : synsec secret retirer <coffre> <chemin> <utilisateur>")
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		p, err := resolveVault(ctx, db, fs.Arg(0))
		if err != nil {
			return err
		}
		loc := store.SecretLocation{ProjectID: p.ID, Env: *env, Name: fs.Arg(1)}
		secret, err := db.SecretMeta(ctx, loc)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("aucun secret nommé %s dans « %s »", fs.Arg(1), p.Name)
		}
		if err != nil {
			return err
		}
		u, err := resolveUser(ctx, db, fs.Arg(2))
		if err != nil {
			return err
		}

		if err := db.RemoveSecretShare(ctx, secret.ID, u.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("%s n'était pas partagé avec « %s »", secret.Name, u.Username)
			}
			return err
		}
		fmt.Printf("%s n'est plus partagé avec « %s ».\n", secret.Name, u.Username)
		return nil
	})
}
