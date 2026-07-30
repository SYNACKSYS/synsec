package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"synsec/internal/alert"
	"synsec/internal/store"
	"synsec/internal/vault"
)

// Configuring the alerts from the command line.
//
// Everything here is held to the account the server was set up with, reading
// included: what it shows is the address of the webhook, which is very often
// the credential itself, and the key that signs the messages. A read-only
// display that hands both to anyone standing at the machine would be a
// strange thing to leave next to a vault.

func runAlerts(args []string) error {
	if len(args) == 0 {
		return runAlertsShow(args)
	}

	switch args[0] {
	case "webhook":
		return runAlertsWebhook(args[1:])
	case "niveau", "level":
		return runAlertsLevel(args[1:])
	case "activer", "on":
		return runAlertsSwitch(args[1:], true)
	case "desactiver", "désactiver", "off":
		return runAlertsSwitch(args[1:], false)
	case "test":
		return runAlertsTest(args[1:])
	case "-h", "--help", "help":
		return usageAlerts()
	default:
		// A bare "synsec alertes -data ..." is a display, not a mistake.
		if strings.HasPrefix(args[0], "-") {
			return runAlertsShow(args)
		}
		return fmt.Errorf("sous-commande inconnue : alertes %q", args[0])
	}
}

func usageAlerts() error {
	fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec alertes - prévenir quand quelque chose sort de l'ordinaire

  synsec alertes                                 état actuel
  synsec alertes webhook <adresse>               où prévenir
  synsec alertes webhook ""                      oublier l'adresse
  synsec alertes niveau <critique|avertissement|info>
  synsec alertes activer | desactiver
  synsec alertes test                            envoyer un message tout de suite

SYNSEC envoie un POST JSON signé à l'adresse indiquée : Home Assistant, ntfy,
Gotify, un salon Discord, ou ton propre script. Rien ne passe par un service
tiers, il n'y a aucun quota.

Trois niveaux :
  critique       refus d'accès, suppressions, serveur rouvert avec le code
  avertissement  ajoute les accès donnés, les appareils, les comptes, les règles
  info           ajoute les mots de passe ratés, les imports, les adresses neuves

Les valeurs des secrets ne sortent jamais. Le nom du coffre et celui du secret,
si : le message part chez toi.

Ces commandes demandent le mot de passe du compte principal.
`)+"\n")
	return nil
}

// withAlertAdmin opens the vault, identifies the caller and checks that this
// is the account the server belongs to.
func withAlertAdmin(dataDir, who string, fn func(ctx context.Context, m *vault.Manager, user store.User) error) error {
	return withManager(dataDir, func(ctx context.Context, m *vault.Manager) error {
		user, err := authenticate(ctx, m.DB(), who)
		if err != nil {
			return err
		}
		if !user.IsRoot {
			return errors.New("les alertes appartiennent au compte principal du serveur, " +
				"celui avec lequel il a été installé")
		}
		return fn(ctx, m, user)
	})
}

func runAlertsShow(args []string) error {
	fs := flag.NewFlagSet("alertes", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}

	return withAlertAdmin(*dataDir, *who, func(ctx context.Context, m *vault.Manager, _ store.User) error {
		url, err := m.SealedSetting(ctx, alert.SettingURL, "")
		if err != nil {
			return err
		}
		secret, err := m.SealedSetting(ctx, alert.SettingSecret, "")
		if err != nil {
			return err
		}
		enabled, err := m.DB().ServerSetting(ctx, alert.SettingEnabled, "")
		if err != nil {
			return err
		}
		level, err := m.DB().ServerSetting(ctx, alert.SettingLevel, alert.SeverityWarning.String())
		if err != nil {
			return err
		}

		fmt.Println()
		fmt.Printf("  État     : %s\n", onOff(enabled == "1"))
		fmt.Printf("  Niveau   : %s\n", level)
		if url == "" {
			fmt.Println("  Webhook  : aucun")
			fmt.Println()
			fmt.Println("  Indique où prévenir :")
			fmt.Println("    synsec alertes webhook https://domotique:8123/api/webhook/synsec -user <nom>")
			fmt.Println()
			return nil
		}
		fmt.Printf("  Webhook  : %s\n", url)
		fmt.Printf("  Clé      : %s\n", secret)
		fmt.Println()
		fmt.Println("  La clé signe chaque message, en-tête X-SYNSEC-Signature :")
		fmt.Println("    sha256_hmac(clé, X-SYNSEC-Timestamp + \".\" + corps)")
		fmt.Println()
		return nil
	})
}

func onOff(on bool) string {
	if on {
		return "actives"
	}
	return "éteintes"
}

func runAlertsWebhook(args []string) error {
	fs := flag.NewFlagSet("alertes webhook", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage : synsec alertes webhook <adresse> -user <nom>")
	}

	return withAlertAdmin(*dataDir, *who, func(ctx context.Context, m *vault.Manager, user store.User) error {
		secret, err := alert.SaveWebhook(ctx, m, fs.Arg(0))
		if err != nil {
			return err
		}
		auditCLI(ctx, m.DB(), user, "", "server.policy", "webhook d'alerte modifié")

		if fs.Arg(0) == "" {
			fmt.Println("Adresse oubliée. Plus rien ne sera envoyé.")
			return nil
		}
		fmt.Println()
		fmt.Println("Adresse enregistrée. Clé de signature :")
		fmt.Println()
		fmt.Printf("  %s\n", secret)
		fmt.Println()
		fmt.Println("Recopie-la dans ce qui reçoit, puis vérifie :")
		fmt.Println("  synsec alertes test -user <nom>")
		fmt.Println()
		return nil
	})
}

func runAlertsLevel(args []string) error {
	fs := flag.NewFlagSet("alertes niveau", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage : synsec alertes niveau <critique|avertissement|info>")
	}
	sev, ok := alert.ParseSeverity(fs.Arg(0))
	if !ok {
		return fmt.Errorf("niveau inconnu %q - critique, avertissement ou info", fs.Arg(0))
	}

	return withAlertAdmin(*dataDir, *who, func(ctx context.Context, m *vault.Manager, user store.User) error {
		if err := m.DB().SetServerSetting(ctx, alert.SettingLevel, sev.String()); err != nil {
			return err
		}
		auditCLI(ctx, m.DB(), user, "", "server.policy", "niveau d'alerte : "+sev.String())
		fmt.Printf("Niveau : %s.\n", sev)
		return nil
	})
}

func runAlertsSwitch(args []string, on bool) error {
	fs := flag.NewFlagSet("alertes", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}

	return withAlertAdmin(*dataDir, *who, func(ctx context.Context, m *vault.Manager, user store.User) error {
		if on {
			// Armed with nowhere to send is the state where somebody believes
			// they are being watched over and are not.
			url, err := m.SealedSetting(ctx, alert.SettingURL, "")
			if err != nil {
				return err
			}
			if url == "" {
				return errors.New("aucune adresse enregistrée : commence par « synsec alertes webhook <adresse> »")
			}
		}
		stored := ""
		if on {
			stored = "1"
		}
		if err := m.DB().SetServerSetting(ctx, alert.SettingEnabled, stored); err != nil {
			return err
		}
		auditCLI(ctx, m.DB(), user, "", "server.policy", "alertes "+onOff(on))

		if on {
			fmt.Println("Alertes actives.")
			return nil
		}
		fmt.Println("Alertes éteintes. Le journal, lui, continue de tout enregistrer.")
		return nil
	})
}

func runAlertsTest(args []string) error {
	fs := flag.NewFlagSet("alertes test", flag.ExitOnError)
	dataDir := fs.String("data", "", "dossier de données")
	who := identityFlag(fs)
	if err := fs.Parse(permute(fs, args)); err != nil {
		return err
	}

	return withAlertAdmin(*dataDir, *who, func(ctx context.Context, m *vault.Manager, _ store.User) error {
		hostname, _ := os.Hostname()
		cfg, err := alert.LoadConfig(ctx, m, hostname)
		if err != nil {
			return err
		}
		// The test works before the switch is flipped: checking an address
		// must not require arming a system nobody has checked.
		if cfg.Webhook.URL == "" {
			url, err := m.SealedSetting(ctx, alert.SettingURL, "")
			if err != nil {
				return err
			}
			if url == "" {
				return errors.New("aucune adresse enregistrée : commence par « synsec alertes webhook <adresse> »")
			}
			secret, err := m.SealedSetting(ctx, alert.SettingSecret, "")
			if err != nil {
				return err
			}
			cfg.Webhook.URL, cfg.Webhook.Secret, cfg.Webhook.Server = url, secret, hostname
		}

		ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()

		w := alert.NewWatcher(m.DB(), func(context.Context) (alert.Config, error) { return cfg, nil })
		if err := w.Test(ctx, cfg); err != nil {
			return fmt.Errorf("le message n'est pas parti : %w", err)
		}
		fmt.Println("Message de test envoyé. Regarde ce qui l'a reçu.")
		return nil
	})
}
