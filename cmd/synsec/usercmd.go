package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"

	"synsec/internal/auth"
	"synsec/internal/store"
)

func runUser(args []string) error {
	if len(args) == 0 {
		return usageUser()
	}

	switch args[0] {
	case "create", "new":
		return runUserCreate(args[1:])
	case "list", "ls":
		return runUserList(args[1:])
	case "passwd", "password":
		return runUserPasswd(args[1:])
	case "rm", "delete":
		return runUserRemove(args[1:])
	case "-h", "--help", "help":
		return usageUser()
	default:
		return fmt.Errorf("sous-commande inconnue : utilisateur %q", args[0])
	}
}

func usageUser() error {
	fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec utilisateur - gère les comptes de l'interface web

  synsec utilisateur create <nom> [-admin]
  synsec utilisateur list
  synsec utilisateur passwd <nom>
  synsec utilisateur rm <nom>

Le mot de passe est demandé à l'écran, sans être affiché.

Une fois le premier administrateur créé, la gestion des comptes passe par
l'interface web. Depuis la ligne de commande, create, passwd et rm exigent
le code de récupération imprimé à l'installation : atteindre le dossier de
données ne suffit pas à s'accorder un accès.
`)+"\n")
	return nil
}

func runUserCreate(args []string) error {
	fs := flag.NewFlagSet("utilisateur create", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	admin := fs.Bool("admin", false, "compte administrateur")
	displayName := fs.String("nom", "", "nom affiché")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage : synsec utilisateur create <nom>")
	}
	username := fs.Arg(0)

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		// The first account is always an administrator: a server whose only
		// user cannot administer it is a server nobody can set up. It is also
		// the only one the command line creates freely - nobody can be signed
		// in yet, so there is no interface to create it from.
		count, err := db.CountUsers(ctx)
		if err != nil {
			return err
		}
		if count > 0 {
			if err := requireRecoveryCode(ctx, db, dataDirOf(*dataDir)); err != nil {
				return err
			}
		}
		isAdmin := *admin || count == 0

		password, err := promptNewPasswordFor(username)
		if err != nil {
			return err
		}
		cred, err := auth.HashPassword(password)
		if err != nil {
			return err
		}

		name := *displayName
		if name == "" {
			name = username
		}

		// The very first account is also the one that reads the audit log and
		// decides who else may. Nothing later can claim that place: the flag is
		// set here and nowhere else.
		u := store.User{
			Username: username, DisplayName: name,
			IsAdmin: isAdmin, IsRoot: count == 0,
		}
		if err := db.CreateUser(ctx, &u, cred); err != nil {
			if store.IsConstraintViolation(err) {
				return fmt.Errorf("un compte nommé %q existe déjà", username)
			}
			return err
		}

		role := "utilisateur"
		if isAdmin {
			role = "administrateur"
		}
		fmt.Printf("Compte %s « %s » créé.\n", role, u.Username)
		return nil
	})
}

func runUserList(args []string) error {
	fs := flag.NewFlagSet("utilisateur list", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		users, err := db.ListUsers(ctx)
		if err != nil {
			return err
		}
		if len(users) == 0 {
			fmt.Println("Aucun compte. Crée le premier avec : synsec utilisateur create <nom>")
			return nil
		}

		w := newTabWriter()
		fmt.Fprintln(w, "NOM\tAFFICHÉ\tRÔLE\tCRÉÉ LE\tDERNIÈRE CONNEXION")
		for _, u := range users {
			role := "utilisateur"
			switch {
			case u.IsRoot:
				role = "principal"
			case u.IsAdmin:
				role = "admin"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				u.Username, u.DisplayName, role,
				formatTime(u.CreatedAt), formatTime(u.LastLoginAt))
		}
		return w.Flush()
	})
}

func runUserPasswd(args []string) error {
	fs := flag.NewFlagSet("utilisateur passwd", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage : synsec utilisateur passwd <nom>")
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		u, err := db.UserByUsername(ctx, fs.Arg(0))
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("aucun compte nommé %q", fs.Arg(0))
		}
		if err != nil {
			return err
		}

		// Taking over an existing account is as good as creating one.
		if err := requireRecoveryCode(ctx, db, dataDirOf(*dataDir)); err != nil {
			return err
		}

		password, err := promptNewPasswordFor(u.Username)
		if err != nil {
			return err
		}
		cred, err := auth.HashPassword(password)
		if err != nil {
			return err
		}

		if err := db.SetUserCredentials(ctx, u.ID, cred); err != nil {
			return err
		}
		// Changing a password has to close every open browser: otherwise a
		// password changed because it leaked would leave the leak in place.
		if err := db.DeleteUserSessions(ctx, u.ID); err != nil {
			return err
		}

		fmt.Printf("Mot de passe de « %s » modifié. Toutes ses sessions sont fermées.\n", u.Username)
		return nil
	})
}

func runUserRemove(args []string) error {
	fs := flag.NewFlagSet("utilisateur rm", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage : synsec utilisateur rm <nom>")
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		u, err := db.UserByUsername(ctx, fs.Arg(0))
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("aucun compte nommé %q", fs.Arg(0))
		}
		if err != nil {
			return err
		}

		// Removing an account is not a way in, but it is a way to strand a
		// vault, so it is held to the same proof.
		if err := requireRecoveryCode(ctx, db, dataDirOf(*dataDir)); err != nil {
			return err
		}

		// The account the server was set up with holds the audit log and is
		// the only one that can open it to anyone else. Nothing can take that
		// place afterwards, so the door would stay shut for good.
		if u.IsRoot {
			return errors.New("c'est le compte principal du serveur, il ne se supprime pas")
		}

		// Removing the last administrator would lock everyone out of the web
		// interface for good, with no way back in but the command line.
		if u.IsAdmin {
			admins, err := countAdmins(ctx, db)
			if err != nil {
				return err
			}
			if admins <= 1 {
				return errors.New("c'est le dernier administrateur : crée-en un autre avant de supprimer celui-ci")
			}
		}

		// Since administrators no longer see vaults nobody shared with them,
		// deleting the only manager of a vault would strand it for good.
		orphaned, err := db.SoleManagerVaults(ctx, u.ID)
		if err != nil {
			return err
		}
		if len(orphaned) > 0 {
			names := make([]string, 0, len(orphaned))
			for _, p := range orphaned {
				names = append(names, "« "+p.Name+" »")
			}
			return fmt.Errorf("« %s » est le seul gestionnaire de %s.\n"+
				"        Donne la gestion à quelqu'un d'autre avant de supprimer ce compte :\n"+
				"          synsec coffre partager <coffre> <utilisateur> -role gestion -user <nom>",
				u.Username, strings.Join(names, ", "))
		}

		if err := db.DeleteUser(ctx, u.ID); err != nil {
			return err
		}
		fmt.Printf("Compte « %s » supprimé.\n", u.Username)
		return nil
	})
}

func countAdmins(ctx context.Context, db *store.DB) (int, error) {
	users, err := db.ListUsers(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range users {
		if u.IsAdmin {
			n++
		}
	}
	return n, nil
}

// promptNewPassword asks twice, without echoing.
//
// Echoing would leave the password in the terminal scrollback, and on a shared
// machine in whatever records that scrollback. Asking twice catches the typo
// that would otherwise lock the owner out of their own server.
func promptNewPassword() (string, error) {
	return promptNewPasswordFor("")
}

// promptNewPasswordFor asks twice and refuses what guessing tries first.
func promptNewPasswordFor(username string) (string, error) {
	first, err := promptPassword("Mot de passe : ")
	if err != nil {
		return "", err
	}
	if len([]rune(first)) < auth.MinPasswordLength {
		return "", auth.ErrPasswordTooShort
	}

	if err := auth.CheckPasswordStrength(first, username); err != nil {
		return "", passwordAdvice(err)
	}

	second, err := promptPassword("Confirmation : ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("les deux saisies diffèrent")
	}
	return first, nil
}

// piped is the single reader over standard input, built on first use.
//
// One for the whole process, not one per prompt: a buffered reader takes more
// than the line it hands back, so a second reader over the same pipe finds the
// rest already gone. Building one each time made every two-prompt flow -
// creating an account, changing a password - fail at the confirmation with
// EOF, which is exactly the provisioning case this path exists for.
var (
	piped     *bufio.Reader
	pipedOnce sync.Once
)

func pipedInput() *bufio.Reader {
	pipedOnce.Do(func() { piped = bufio.NewReader(os.Stdin) })
	return piped
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// Piped input, typically a provisioning script. Nothing is echoed by
		// definition, so reading a line is enough.
		line, err := pipedInput().ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("lecture du mot de passe : %w", err)
		}
		fmt.Fprintln(os.Stderr)
		return strings.TrimRight(line, "\r\n"), nil
	}

	raw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("lecture du mot de passe : %w", err)
	}
	return string(raw), nil
}

// passwordAdvice turns a refusal into something worth reading at a terminal.
func passwordAdvice(err error) error {
	switch {
	case errors.Is(err, auth.ErrPasswordTooShort):
		return fmt.Errorf("le mot de passe doit faire au moins %d caractères", auth.MinPasswordLength)
	case errors.Is(err, auth.ErrPasswordTooLong):
		return errors.New("ce mot de passe est trop long")
	case errors.Is(err, auth.ErrPasswordTooCommon):
		return errors.New("ce mot de passe est parmi les premiers essayés par une attaque, prends autre chose")
	default:
		return err
	}
}
