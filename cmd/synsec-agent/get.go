package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
)

// runGet writes one value, raw, so that it can be piped or captured.
func runGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	var c config
	bindFlags(fs, &c)
	newline := fs.Bool("n", false, "terminer par un retour à la ligne")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage : synsec-agent get <identifiant>")
	}

	client, err := newClient(&c)
	if err != nil {
		return err
	}

	value, err := client.value(context.Background(), fs.Arg(0))
	if err != nil {
		return err
	}

	// No trailing newline by default: a password read into a variable must not
	// come back with one glued to it.
	fmt.Print(value)
	if *newline {
		fmt.Println()
	}
	return nil
}

// runList names what the token reaches, without any value.
func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	var c config
	bindFlags(fs, &c)
	showEnv := fs.Bool("env", false, "afficher aussi le nom de variable correspondant")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client, err := newClient(&c)
	if err != nil {
		return err
	}

	names, err := client.list(context.Background())
	if err != nil {
		return err
	}
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "Ce jeton n'atteint aucun secret.")
		return nil
	}
	sort.Strings(names)

	for _, name := range names {
		if *showEnv {
			fmt.Printf("%s\t%s\n", name, envName(c.prefix, name))
			continue
		}
		fmt.Println(name)
	}
	return nil
}
