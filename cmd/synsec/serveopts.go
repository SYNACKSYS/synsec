package main

import (
	"flag"
	"fmt"
	"strings"

	"synsec/internal/config"
)

// The options `serve` accepts, declared once.
//
// `synsec service install` takes the same ones and writes them into the
// service definition, so a server installed with a policy keeps it after a
// reboot. Declared in two places, they drift; the day one of them gained
// -require-2fa and the other did not, the only way to set it on a service was
// an environment variable nobody had documented.

// serveOptions declares the shared flags on fs and returns the function that
// folds them into cfg once Parse has run.
//
// The fold is deferred because three of them cannot be written straight into a
// field: two are comma-separated lists, and the third is a switch whose third
// state is "not mentioned", which only fs.Visit can tell apart from false.
func serveOptions(fs *flag.FlagSet, cfg *config.Config) func() {
	fs.StringVar(&cfg.DataDir, "data", cfg.DataDir, "dossier de données")
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "adresse d'écoute")
	// Les défauts sont les valeurs déjà résolues depuis l'environnement, sans
	// quoi l'option écraserait SYNSEC_TLS_CERT par une chaîne vide.
	fs.StringVar(&cfg.TLSCert, "tls-cert", cfg.TLSCert,
		"certificat TLS, chaîne complète (défaut : auto-signé)")
	fs.StringVar(&cfg.TLSKey, "tls-key", cfg.TLSKey, "clé privée du certificat")
	fs.DurationVar(&cfg.SessionIdle, "session-idle", cfg.SessionIdle,
		"délai d'inactivité avant déconnexion de l'interface web")
	fs.DurationVar(&cfg.AuditRetain, "audit-retain", cfg.AuditRetain,
		"durée de conservation du journal d'audit (0 = sans limite)")

	trustedProxies := fs.String("trusted-proxies", "",
		"adresses des proxies dont X-Forwarded-For est cru, séparées par des virgules")
	webAllow := fs.String("web-allow", "",
		"restreint l'interface web à ces adresses ou blocs CIDR, séparés par des virgules")
	require2FA := fs.Bool("require-2fa", false,
		"impose un second facteur à tous les comptes, et interdit à l'interface de revenir dessus")

	return func() {
		if *trustedProxies != "" {
			cfg.TrustedProxies = splitList(*trustedProxies)
		}
		if *webAllow != "" {
			cfg.WebAllow = splitList(*webAllow)
		}
		// Mentioned or not is the distinction that matters: unmentioned leaves
		// the decision to the interface, mentioned settles it either way.
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "require-2fa" {
				value := *require2FA
				cfg.RequireSecondFactor = &value
			}
		})
	}
}

// serveArgs rebuilds the command line a service should run.
//
// Only what differs from the defaults, so the service definition stays
// readable and a setting that was never chosen does not look deliberate.
func serveArgs(cfg config.Config) []string {
	defaults := config.Default()

	args := []string{"serve", "-data", cfg.DataDir, "-listen", cfg.Listen}

	if cfg.TLSCert != "" {
		args = append(args, "-tls-cert", cfg.TLSCert)
	}
	if cfg.TLSKey != "" {
		args = append(args, "-tls-key", cfg.TLSKey)
	}
	if len(cfg.TrustedProxies) > 0 {
		args = append(args, "-trusted-proxies", strings.Join(cfg.TrustedProxies, ","))
	}
	if len(cfg.WebAllow) > 0 {
		args = append(args, "-web-allow", strings.Join(cfg.WebAllow, ","))
	}
	if cfg.SessionIdle != defaults.SessionIdle {
		args = append(args, "-session-idle", cfg.SessionIdle.String())
	}
	if cfg.AuditRetain != 0 {
		args = append(args, "-audit-retain", cfg.AuditRetain.String())
	}
	if cfg.RequireSecondFactor != nil {
		// One token with an equals sign: a boolean flag written as two
		// arguments would leave the value parsed as the next flag.
		args = append(args, fmt.Sprintf("-require-2fa=%t", *cfg.RequireSecondFactor))
	}
	return args
}
