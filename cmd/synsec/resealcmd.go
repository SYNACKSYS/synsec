package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"synsec/internal/vault"
)

// Remettre la clé sous la meilleure protection disponible.
//
// Une installation garde la protection choisie le jour de sa mise en place, et
// ne la rediscute jamais toute seule. C'est délibéré : une machine qui perd son
// TPM doit échouer bruyamment plutôt que retomber en silence sur plus faible.
// Mais la conséquence est qu'une machine qui en gagne un ne s'en sert pas non
// plus, et personne ne le devine. D'où cette commande, qui est le seul endroit
// où le choix se rejoue.

func runMaintenanceReseal(args []string) error {
	fs := flag.NewFlagSet("maintenance sceller", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}

	return withManager(*dataDir, func(ctx context.Context, m *vault.Manager) error {
		ready, err := m.Initialized(ctx)
		if err != nil {
			return err
		}
		if !ready {
			return errors.New("ce serveur n'est pas encore préparé - lance : synsec init")
		}

		actuel, err := m.CurrentProvider(ctx)
		if err != nil {
			return err
		}
		meilleur := m.BestProvider()

		fmt.Println()
		fmt.Printf("  Protection actuelle : %s\n", actuel)
		fmt.Printf("  Meilleure ici       : %s\n", meilleur.Name())
		fmt.Println()

		if actuel == meilleur.Name() {
			fmt.Println("  Rien à faire : cette machine n'offre pas mieux.")
			fmt.Println()
			return nil
		}

		// L'identité est demandée parce que le geste déplace la garde de la
		// clé racine. Il ne donne accès à rien de nouveau, mais il change ce
		// qui ouvrira le coffre au prochain démarrage, et le journal doit
		// nommer qui l'a décidé.
		user, err := authenticate(ctx, m.DB(), *who)
		if err != nil {
			return err
		}

		// Descellé d'abord avec la protection en place : sans la clé racine en
		// mémoire, il n'y a rien à re-sceller.
		if err := m.Unseal(ctx); err != nil {
			return fmt.Errorf("impossible d'ouvrir le coffre avec la protection actuelle : %w\n"+
				"        Si cette machine a changé, passe par : synsec recover", err)
		}
		defer m.Seal()

		provider, err := m.ReprovisionMachineSlot(ctx)
		if err != nil {
			return fmt.Errorf("le re-scellement a échoué, la protection précédente reste en place : %w", err)
		}

		// Vérification immédiate plutôt que promesse : on referme et on rouvre
		// avec ce qui vient d'être écrit. Découvrir au prochain redémarrage
		// que le nouveau scellement ne s'ouvre pas serait découvrir trop tard.
		m.Seal()
		if err := m.Unseal(ctx); err != nil {
			return fmt.Errorf("le nouveau scellement ne se rouvre pas : %w\n"+
				"        Utilise le code de récupération : synsec recover", err)
		}

		auditCLI(ctx, m.DB(), user, "", "vault.reseal", actuel+" -> "+provider.Name())

		fmt.Printf("  Clé re-scellée : %s\n", provider.Name())
		fmt.Printf("  %s\n", wrap(provider.Protection().Summary, 66, "  "))
		if c := provider.Protection().Caveat; c != "" {
			fmt.Println()
			fmt.Printf("  À savoir : %s\n", wrap(c, 66, "  "))
		}
		fmt.Println()
		fmt.Println("  Vérifié ici : le coffre se rouvre sous ce compte.")
		fmt.Println()
		fmt.Println("  Le service, lui, tourne en LocalSystem. Redémarre-le")
		fmt.Println("  maintenant, pendant que tu es devant la machine, plutôt")
		fmt.Println("  que de le découvrir à la prochaine coupure de courant :")
		fmt.Println()
		fmt.Println("    net stop SYNSEC")
		fmt.Println("    net start SYNSEC")
		fmt.Println("    curl https://localhost:8787/api/v1/health")
		fmt.Println()
		fmt.Println("  La réponse attendue est {\"status\":\"ready\"}. Si elle dit")
		fmt.Println("  « sealed », le service n'a pas su ouvrir la clé : reviens")
		fmt.Println("  en arrière avec le code de récupération, synsec recover.")
		fmt.Println()
		fmt.Println("  Le code imprimé à l'installation reste valable.")
		fmt.Println()
		return nil
	})
}

// providerLabel donne le nom lisible d'un fournisseur, pour les messages.
func providerLabel(name string) string {
	switch name {
	case "windows-tpm":
		return "puce TPM (Windows)"
	case "systemd-tpm2":
		return "puce TPM (Linux)"
	case "dpapi":
		return "Windows DPAPI"
	case "keyfile":
		return "fichier sur le disque"
	}
	return name
}
