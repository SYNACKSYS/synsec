package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// runRun launches a program with the secrets in its environment.
//
// This is the whole point of the agent: the values exist in one process's
// memory, are handed to a child, and are gone when it exits. Nothing is
// written to a file that somebody has to remember to delete.
func runRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var c config
	bindFlags(fs, &c)
	quiet := fs.Bool("quiet", false, "ne pas écrire le résumé sur la sortie d'erreur")

	// Everything after "--" belongs to the child, including its own flags.
	agentArgs, childArgs := splitAtDoubleDash(args)
	if err := fs.Parse(agentArgs); err != nil {
		return err
	}
	if len(childArgs) == 0 {
		childArgs = fs.Args()
	}
	if len(childArgs) == 0 {
		return errors.New("indique le programme à lancer : synsec-agent run -- <commande>")
	}

	client, err := newClient(&c)
	if err != nil {
		return err
	}

	ctx := context.Background()
	names, err := selectNames(ctx, client, c.names)
	if err != nil {
		return err
	}
	if first, second, clash := collide(c.prefix, names); clash {
		return fmt.Errorf("« %s » et « %s » donneraient la même variable %s",
			first, second, envName(c.prefix, first))
	}

	values, err := client.fetch(ctx, names)
	if err != nil {
		return err
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "synsec-agent : %d %s injecté%s\n",
			len(values), plural(len(values), "secret", "secrets"), plural(len(values), "", "s"))
	}

	return execute(childArgs, environWith(os.Environ(), c.prefix, values))
}

// execute runs the child, forwards the signals it should receive, and exits
// with its status so that whatever supervises the agent sees the truth.
func execute(argv []string, env []string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("lancement de %q : %w", argv[0], err)
	}

	// A wrapper that swallowed Ctrl+C, or a systemd stop, would leave the
	// child running with the secrets still in it.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	for {
		select {
		case sig := <-signals:
			// Windows cannot deliver a signal to another process; there the
			// console already passes Ctrl+C to the whole group, so a failure
			// here is expected rather than worth reporting.
			_ = cmd.Process.Signal(sig)
		case err := <-done:
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				os.Exit(exit.ExitCode())
			}
			return err
		}
	}
}

// environWith adds the secrets to a copy of the current environment.
//
// The parent's variables are kept: a program still needs PATH, HOME and the
// rest. A secret that collides with an existing name wins, because it is the
// one the caller asked for.
func environWith(base []string, prefix string, values map[string]string) []string {
	out := make([]string, 0, len(base)+len(values))
	injected := make(map[string]bool, len(values))
	for name, value := range values {
		env := envName(prefix, name)
		if env == "" {
			continue
		}
		injected[env] = true
		out = append(out, env+"="+value)
	}

	for _, entry := range base {
		if name, _, ok := cut(entry, '='); ok && injected[name] {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func cut(s string, sep byte) (before, after string, found bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// splitAtDoubleDash separates the agent's own options from the command line it
// is asked to run.
//
// Done by hand because the standard flag package stops at the first
// non-flag argument, which would leave "-v" in "run -- ls -v" being parsed as
// an option of the agent.
func splitAtDoubleDash(args []string) (mine, child []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func plural(n int, one, many string) string {
	if n <= 1 {
		return one
	}
	return many
}
