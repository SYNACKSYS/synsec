package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"synsec/internal/auth"
	"synsec/internal/config"
	"synsec/internal/store"
)

func runToken(args []string) error {
	if len(args) == 0 {
		return usageToken()
	}

	switch args[0] {
	case "create", "new":
		return runTokenCreate(args[1:])
	case "list", "ls":
		return runTokenList(args[1:])
	case "revoke":
		return runTokenRevoke(args[1:])
	case "portee":
		return runTokenScope(args[1:])
	case "-h", "--help", "help":
		return usageToken()
	default:
		return fmt.Errorf("sous-commande inconnue : token %q", args[0])
	}
}

func usageToken() error {
	fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec token - connecte un appareil à un coffre

  synsec token create <coffre> <nom> [-write] [-expires 720h] [-ip 192.168.1.10]
                                     [-secret mqtt_password,cle_wifi] -user <nom>
  synsec token list   [coffre]
  synsec token portee <identifiant> [secret,secret] [-user <nom>]
  synsec token revoke <identifiant>

Le token n'est affiché qu'une seule fois, à sa création.

Créer un token, ou changer sa portée, demande le mot de passe d'un compte qui
gère le coffre. Le révoquer ne demande rien : retirer un accès ne se refuse
pas.

Sans -secret, le token atteint tout le coffre. Avec, il n'atteint que ce qui
est nommé - et un secret créé ensuite ne s'y ajoute pas tout seul.
`)+"\n")
	return nil
}

func runTokenCreate(args []string) error {
	fs := flag.NewFlagSet("token create", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	env := fs.String("env", store.DefaultEnvironment, "environnement")
	write := fs.Bool("write", false, "autoriser l'écriture")
	expires := fs.Duration("expires", 0, "durée de validité (0 = illimitée)")
	ips := fs.String("ip", "", "adresses autorisées, séparées par des virgules (IP ou CIDR)")
	secrets := fs.String("secret", "", "secrets accessibles, séparés par des virgules (défaut : tout le coffre)")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage : synsec token create <coffre> <nom> -user <compte>")
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		p, err := resolveVault(ctx, db, fs.Arg(0))
		if err != nil {
			return err
		}

		// A token is a credential that works from anywhere on the network,
		// without a password, until somebody revokes it. Minting one is
		// therefore an act that grants access, and it is held to the same
		// proof as any other: who are you, and may you manage this vault.
		//
		// Without this, reaching the data directory was enough to walk away
		// with a durable remote credential that no line of the journal
		// attributed to anyone.
		user, err := authenticate(ctx, db, *who)
		if err != nil {
			return err
		}
		if err := requireVaultRole(ctx, db, user, p, store.RoleManager); err != nil {
			return err
		}

		id, err := store.NewID()
		if err != nil {
			return err
		}
		plaintext, hash, err := auth.NewServiceToken(id)
		if err != nil {
			return err
		}

		tok := store.ServiceToken{
			ID:          id,
			Name:        fs.Arg(1),
			ProjectID:   p.ID,
			Env:         *env,
			CanWrite:    *write,
			IPAllowlist: splitList(*ips),
			Secrets:     splitList(*secrets),
			CreatedBy:   user.Username,
		}
		if *expires > 0 {
			tok.ExpiresAt = time.Now().Add(*expires)
		}
		if err := db.CreateServiceToken(ctx, &tok, hash); err != nil {
			return err
		}

		auditCLI(ctx, db, user, p.ID, "token.create", tok.Name)
		printToken(p, tok, plaintext)
		return nil
	})
}

// printToken shows the credential and, right underneath, the snippet to paste.
//
// Handing someone a bare token and leaving them to work out the Authorization
// header is where a tool stops being usable by anyone who is not already a
// developer.
func printToken(p store.Project, tok store.ServiceToken, plaintext string) {
	line := strings.Repeat("=", 66)

	fmt.Println()
	fmt.Println(line)
	fmt.Printf("  Token pour « %s » - coffre « %s »\n", tok.Name, p.Name)
	fmt.Println(line)
	fmt.Println()
	fmt.Printf("  %s\n", plaintext)
	fmt.Println()
	fmt.Println("  Copie-le maintenant : il ne sera plus jamais affiché.")
	fmt.Println()
	fmt.Printf("  Portée   : %s%s\n", tokenScope(tok), writeSuffix(tok.CanWrite))
	fmt.Printf("  Validité : %s\n", formatExpiry(tok.ExpiresAt))
	if len(tok.IPAllowlist) > 0 {
		fmt.Printf("  Adresses : %s\n", strings.Join(tok.IPAllowlist, ", "))
	}
	fmt.Println()
	fmt.Println(line)
	fmt.Println()
	fmt.Println("  Récupérer les secrets, en une requête :")
	fmt.Println()
	for _, l := range fetchExample(plaintext) {
		fmt.Printf("    %s\n", l)
	}
	fmt.Println()
	fmt.Println("  Home Assistant (secrets.yaml) :")
	fmt.Println()
	fmt.Printf("    synsec_token: \"%s\"\n", plaintext)
	fmt.Println()
}

// fetchExample returns a command the owner can paste as-is.
//
// Two details learned the hard way: a "<serveur>" placeholder gets pasted
// literally, and under cmd the angle bracket is a redirection operator, so the
// failure is an unrelated message about a missing file. And a bash example
// with backslash continuations is useless on the platform most of these
// installations actually run on.
func fetchExample(token string) []string {
	host := "localhost"
	if name, err := os.Hostname(); err == nil && name != "" {
		host = name
	}
	url := fmt.Sprintf("https://%s:%s/api/v1/export", host, config.DefaultPort)

	if runtime.GOOS == "windows" {
		// curl.exe first, deliberately. It ships with Windows and is immune
		// to the two traps that cost an evening: Windows PowerShell 5.1 still
		// negotiates TLS 1.0 by default, which hardened servers refuse, and it
		// caches connection state so a session that failed once keeps failing
		// after the certificate is fixed. Neither is guessable from the error
		// message, which only says the connection was closed.
		return []string{
			fmt.Sprintf("curl.exe -H \"Authorization: Bearer %s\" %s", token, url),
			"",
			"# En PowerShell, la première ligne est indispensable, dans une fenêtre neuve :",
			"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12",
			fmt.Sprintf("Invoke-RestMethod -Uri \"%s\" -Headers @{ Authorization = \"Bearer %s\" }", url, token),
		}
	}
	return []string{
		"# -k accepte le certificat auto-signé",
		fmt.Sprintf("curl -k -H \"Authorization: Bearer %s\" %s", token, url),
	}
}

func writeSuffix(canWrite bool) string {
	if canWrite {
		return " (lecture et écriture)"
	}
	return " (lecture seule)"
}

func runTokenList(args []string) error {
	fs := flag.NewFlagSet("token list", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		projectID := ""
		if fs.NArg() == 1 {
			p, err := resolveVault(ctx, db, fs.Arg(0))
			if err != nil {
				return err
			}
			projectID = p.ID
		}

		tokens, err := db.ListServiceTokens(ctx, projectID)
		if err != nil {
			return err
		}
		if len(tokens) == 0 {
			fmt.Println("Aucun token. Connecte un appareil avec : synsec token create <coffre> <nom>")
			return nil
		}

		now := time.Now()
		w := newTabWriter()
		fmt.Fprintln(w, "NOM\tIDENTIFIANT\tPORTÉE\tÉCRITURE\tÉTAT\tDERNIER USAGE")
		for _, tok := range tokens {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				tok.Name, tok.ID, tokenScope(tok), yesNo(tok.CanWrite),
				tokenState(tok, now), formatTime(tok.LastUsedAt))
		}
		return w.Flush()
	})
}

func tokenState(tok store.ServiceToken, now time.Time) string {
	switch {
	case !tok.RevokedAt.IsZero():
		return "révoqué"
	case !tok.ExpiresAt.IsZero() && !tok.ExpiresAt.After(now):
		return "expiré"
	default:
		return "actif"
	}
}

// tokenScope says what a token reaches, in one column.
func tokenScope(tok store.ServiceToken) string {
	if len(tok.Secrets) == 0 {
		return "tout le coffre"
	}
	return strings.Join(tok.Secrets, ",")
}

// runTokenScope narrows a token, or opens it back to the whole vault.
func runTokenScope(args []string) error {
	fs := flag.NewFlagSet("token portee", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return errors.New("usage : synsec token portee <identifiant> [secret,secret] [-user <compte>]")
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		tok, _, err := db.ServiceToken(ctx, fs.Arg(0))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("token %q inconnu", fs.Arg(0))
			}
			return err
		}

		// With no list, the command reports rather than changes: reading a
		// scope is the more frequent need, and an accidental "portee <id>"
		// must not silently hand the whole vault to a narrowed token.
		if fs.NArg() == 1 {
			fmt.Printf("%s : %s\n", tok.Name, tokenScope(tok))
			return nil
		}

		// Changing a scope can only widen or narrow what an existing remote
		// credential reaches, so it is a grant and asks like one. Creating the
		// token already did; changing it afterwards must not be the cheaper
		// way round.
		p, err := db.Project(ctx, tok.ProjectID)
		if err != nil {
			return err
		}
		user, err := authenticate(ctx, db, *who)
		if err != nil {
			return err
		}
		if err := requireVaultRole(ctx, db, user, p, store.RoleManager); err != nil {
			return err
		}

		names := splitList(fs.Arg(1))
		if err := db.SetTokenSecrets(ctx, tok.ID, names); err != nil {
			return err
		}
		auditCLI(ctx, db, user, p.ID, "token.scope", tok.Name)
		if len(names) == 0 {
			fmt.Printf("%s atteint de nouveau tout le coffre.\n", tok.Name)
			return nil
		}
		fmt.Printf("%s n'atteint plus que : %s\n", tok.Name, strings.Join(names, ", "))
		return nil
	})
}

func runTokenRevoke(args []string) error {
	fs := flag.NewFlagSet("token revoke", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage : synsec token revoke <identifiant>")
	}

	return withStore(*dataDir, func(ctx context.Context, db *store.DB) error {
		if err := db.RevokeServiceToken(ctx, fs.Arg(0), time.Now()); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("token %q inconnu ou déjà révoqué", fs.Arg(0))
			}
			return err
		}
		fmt.Printf("Token %s révoqué. L'appareil ne peut plus lire aucun secret.\n", fs.Arg(0))
		return nil
	})
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
