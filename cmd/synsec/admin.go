package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
	"text/tabwriter"
	"time"

	"synsec/internal/config"
	"synsec/internal/store"
	"synsec/internal/vault"
)

// withStore opens the database for commands that touch no encrypted value.
//
// Creating an account, listing vaults, granting access: none of these need the
// root key. Loading it anyway would hold it in memory for no reason, and would
// make account management impossible on a host whose keystore has been lost -
// exactly when a new account is most likely to be needed.
//
// Administration commands talk to the database directly rather than through
// the HTTP API. That way they keep working when the server is stopped, which
// is also when someone is most likely to need them.
func withStore(dataDir string, fn func(ctx context.Context, db *store.DB) error) error {
	cfg := config.Default()
	if dataDir != "" {
		cfg.DataDir = dataDir
	}
	if err := cfg.Prepare(); err != nil {
		return err
	}

	db, err := store.Open(cfg.DatabasePath())
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	ready, err := vault.New(db, cfg.DataDir).Initialized(ctx)
	if err != nil {
		return err
	}
	if !ready {
		return errors.New("ce serveur n'est pas encore préparé - lance d'abord : synsec init")
	}
	return fn(ctx, db)
}

// withManager additionally unseals the vault, for the commands that actually
// read or write a secret value.
func withManager(dataDir string, fn func(ctx context.Context, m *vault.Manager) error) error {
	cfg := config.Default()
	if dataDir != "" {
		cfg.DataDir = dataDir
	}

	return withStore(dataDir, func(ctx context.Context, db *store.DB) error {
		manager := vault.New(db, cfg.DataDir)
		if err := manager.Unseal(ctx); err != nil {
			return fmt.Errorf("impossible d'ouvrir le coffre : %w\n"+
				"        Si cette machine a été réinstallée, utilise : synsec recover", err)
		}
		defer manager.Seal()

		return fn(ctx, manager)
	})
}

// dataDirOf resolves the data directory a command was given.
func dataDirOf(flagValue string) string {
	cfg := config.Default()
	if flagValue != "" {
		cfg.DataDir = flagValue
	}
	return cfg.DataDir
}

// requireRecoveryCode demands the printed recovery code before an operation
// that would otherwise grant access to someone who has none.
//
// Creating an account is the only thing on the server that hands out a way in
// without any existing way in. Reaching the data directory is not enough of a
// credential: on a machine where the key is sealed to the host, every local
// administrator can open the database, and a silent new account would be an
// unnoticed way into the web interface.
//
// So once the first administrator exists, the command line stops being a
// normal path and becomes a break-glass one: the web interface is where
// accounts are managed, and doing it from a shell means proving you hold the
// kit printed at installation.
func requireRecoveryCode(ctx context.Context, db *store.DB, dataDir string) error {
	fmt.Fprintln(os.Stderr,
		"Cette opération demande le code de récupération imprimé à l'installation.")

	code, err := promptPassword("Code de récupération : ")
	if err != nil {
		return err
	}

	manager := vault.New(db, dataDir)
	if err := manager.CheckRecoveryCode(ctx, code); err != nil {
		if errors.Is(err, vault.ErrBadRecoveryCode) {
			return errors.New("ce code ne correspond pas.\n" +
				"        Les tirets, les espaces et la casse n'ont aucune importance.\n" +
				"        Pour gérer les comptes sans ce code, passe par l'interface web")
		}
		return err
	}
	return nil
}

// resolveVault accepts either a vault name or its identifier, because a person
// types the name and a script pastes the identifier.
func resolveVault(ctx context.Context, db *store.DB, ref string) (store.Project, error) {
	if p, err := db.ProjectByName(ctx, ref); err == nil {
		return p, nil
	}
	p, err := db.Project(ctx, ref)
	if errors.Is(err, store.ErrNotFound) {
		return store.Project{}, fmt.Errorf("aucun coffre nommé %q", ref)
	}
	return p, err
}

// readValue takes a secret from the flag when given, otherwise from standard
// input.
//
// Standard input is the safer route and the one worth encouraging: a value
// passed on the command line ends up in the shell history and, on Linux, in
// the process list where any other user can read it.
func readValue(flagValue string, flagSet bool) ([]byte, error) {
	if flagSet {
		return []byte(flagValue), nil
	}
	// Piped input, typically a provisioning script. The password prompt has
	// already taken its line from the same reader, so what is left is the
	// value - all of it, newlines included.
	//
	// Reading straight from os.Stdin here would swallow the whole stream
	// before the prompt ever ran, and every scripted write would fail on a
	// password that was never asked for. One reader, one order: the identity
	// first, the value after.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		value, err := io.ReadAll(pipedInput())
		if err != nil {
			return nil, fmt.Errorf("lecture de la valeur : %w", err)
		}
		return []byte(strings.TrimRight(string(value), "\r\n")), nil
	}

	fmt.Fprintln(os.Stderr, "Saisis la valeur puis termine par Ctrl+Z (Windows) ou Ctrl+D (Linux) :")

	value, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("lecture de la valeur : %w", err)
	}
	// A trailing newline is what the terminal adds, not what the user meant.
	return []byte(strings.TrimRight(string(value), "\r\n")), nil
}

// permute moves options ahead of positional arguments before parsing.
//
// Go's flag package stops at the first argument that is not an option, so
// "synsec secret set Maison /mqtt -value x" would silently treat the option as
// a third positional argument. Nobody outside Go expects that, and the failure
// is confusing rather than loud, so both orders are accepted here.
func permute(fs *flag.FlagSet, args []string) []string {
	var options, positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Everything after "--" is positional by convention, including things
		// that look like options.
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}

		options = append(options, arg)

		name := strings.TrimLeft(arg, "-")
		if strings.Contains(name, "=") {
			continue // written as -name=value, nothing else to take
		}
		f := fs.Lookup(name)
		if f == nil {
			continue // unknown; let Parse produce the error
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			continue // a boolean carries no separate value
		}
		if i+1 < len(args) {
			i++
			options = append(options, args[i])
		}
	}

	// The separator is re-emitted, not dropped: without it a positional
	// argument that begins with a dash - a password like "-abc" - would go
	// back into option parsing and be rejected as unknown.
	options = append(options, "--")
	return append(options, positional...)
}

func newTabWriter() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04")
}

func formatExpiry(t time.Time) string {
	if t.IsZero() {
		return "jamais"
	}
	return t.Format("2006-01-02")
}

func yesNo(b bool) string {
	if b {
		return "oui"
	}
	return "non"
}
