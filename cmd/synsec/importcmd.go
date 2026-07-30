package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"synsec/internal/importer"
	"synsec/internal/store"
	"synsec/internal/vault"
)

// runImport reads a secrets.yaml or a .env and creates the entries.
//
// This exists because the alternative is retyping thirty secrets by hand, and
// nobody does. Someone convinced by SYNSEC gives up around the eighth.
func runImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	env := fs.String("env", store.DefaultEnvironment, "environnement")
	format := fs.String("format", "", "yaml ou env (défaut : d'après l'extension)")
	dryRun := fs.Bool("essai", false, "montrer ce qui serait fait, sans rien écrire")
	replace := fs.Bool("remplacer", false, "écraser un identifiant déjà pris (nouvelle version)")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage : synsec import <coffre> <fichier>")
	}
	vaultRef, path := fs.Arg(0), fs.Arg(1)

	chosen := *format
	if chosen == "" {
		chosen = importer.DetectFormat(path)
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("ouverture de %s : %w", path, err)
	}
	defer file.Close()

	entries, err := importer.Parse(file, chosen)
	if err != nil {
		return fmt.Errorf("%s : %w", path, err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("%s ne contient aucune entrée", path)
	}

	return withManager(*dataDir, func(ctx context.Context, m *vault.Manager) error {
		p, err := resolveVault(ctx, m.DB(), vaultRef)
		if err != nil {
			return err
		}
		user, err := authenticate(ctx, m.DB(), *who)
		if err != nil {
			return err
		}
		if err := requireVaultRole(ctx, m.DB(), user, p, store.RoleWriter); err != nil {
			return err
		}

		existing, err := m.DB().ListSecrets(ctx, p.ID, *env)
		if err != nil {
			return err
		}
		taken := make(map[string]bool, len(existing))
		for _, s := range existing {
			taken[s.Name] = true
		}

		plan, err := importer.BuildPlan(entries, taken, *replace, store.Slugify)
		if err != nil {
			return err
		}
		printPlan(path, chosen, p.Name, plan)

		if *dryRun {
			fmt.Println("\nEssai : rien n'a été écrit. Relance sans -essai pour importer.")
			return nil
		}
		if plan.ToWrite() == 0 {
			fmt.Println("\nRien à faire.")
			return nil
		}

		written := 0
		for _, item := range plan.Items {
			if item.Skip {
				continue
			}
			loc := store.SecretLocation{ProjectID: p.ID, Env: *env, Name: item.Name}
			if _, err := m.PutSecret(ctx, loc, []byte(item.Entry.Value), item.Entry.Key, user.Username); err != nil {
				return fmt.Errorf("écriture de %s : %w", item.Name, err)
			}
			written++
		}

		auditCLI(ctx, m.DB(), user, p.ID, "secret.import", p.Name)
		fmt.Printf("\n%d secret(s) importé(s) dans « %s ».\n", written, p.Name)
		fmt.Printf("Vérifie-les, puis efface %s : il est toujours en clair.\n", path)
		return nil
	})
}

// printPlan shows what will happen. Values are never printed: the point of the
// exercise is to stop them being readable.
func printPlan(path, format, vaultName string, plan importer.Plan) {
	fmt.Printf("%s (%s) : %d entrée(s) vers « %s »\n\n", path, format, len(plan.Items), vaultName)

	w := newTabWriter()
	fmt.Fprintln(w, "CLÉ\tIDENTIFIANT\tÉTAT")
	for _, item := range plan.Items {
		fmt.Fprintf(w, "%s\t%s\t%s\n", item.Entry.Key, item.Name, item.Reason)
	}
	w.Flush()

	skipped := len(plan.Items) - plan.ToWrite()
	summary := fmt.Sprintf("\n%d à écrire", plan.ToWrite())
	if skipped > 0 {
		summary += fmt.Sprintf(", %d ignoré(s)", skipped)
	}
	fmt.Println(summary)

	if skipped > 0 {
		fmt.Println("Pour écraser les identifiants déjà pris, ajoute -remplacer.")
	}
}

func usageImport() error {
	fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec import - reprend un fichier de secrets existant

  synsec import <coffre> <fichier> [-essai] [-remplacer]

Lit un secrets.yaml de Home Assistant ou un fichier .env, et crée une entrée
par ligne. La clé devient le nom lisible, sa version en identifiant technique
sert aux appareils.

  synsec import Maison secrets.yaml -essai      montre sans rien écrire
  synsec import Maison secrets.yaml             importe
  synsec import Maison .env -remplacer          écrase les identifiants pris

Un identifiant déjà présent est ignoré, sauf avec -remplacer : relancer un
import ne doit pas écrire en silence une seconde version de tout.

Le fichier d'origine n'est ni modifié ni effacé. C'est à toi de le supprimer
une fois l'import vérifié : il contient toujours tout, en clair.
`)+"\n")
	return nil
}

// runImportOrHelp routes -h to the usage text, since import takes its
// arguments directly rather than through a subcommand.
func runImportOrHelp(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "-h", "--help", "help":
			return usageImport()
		}
	}
	if len(args) == 0 {
		return usageImport()
	}
	return runImport(args)
}
