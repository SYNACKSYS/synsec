package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
)

// runEnv writes the secrets as assignments for a shell to evaluate.
//
// Less safe than "run": the values pass through the terminal and, depending on
// the shell, through its history. It exists because an interactive session and
// a Makefile both need it, and because pretending otherwise would only push
// people towards writing a .env file by hand.
func runEnv(args []string) error {
	fs := flag.NewFlagSet("env", flag.ExitOnError)
	var c config
	bindFlags(fs, &c)
	format := fs.String("format", defaultFormat(), "sh, powershell, dotenv ou json")
	if err := fs.Parse(args); err != nil {
		return err
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

	rendered, err := render(*format, c.prefix, values)
	if err != nil {
		return err
	}
	fmt.Print(rendered)
	return nil
}

// defaultFormat guesses what the caller's shell wants.
func defaultFormat() string {
	if runtime.GOOS == "windows" && os.Getenv("SHELL") == "" {
		return "powershell"
	}
	return "sh"
}

func render(format, prefix string, values map[string]string) (string, error) {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	// Sorted so that the output of two runs can be compared.
	sort.Strings(names)

	if format == "json" {
		out := make(map[string]string, len(values))
		for _, name := range names {
			out[envName(prefix, name)] = values[name]
		}
		encoded, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return "", err
		}
		return string(encoded) + "\n", nil
	}

	var b strings.Builder
	for _, name := range names {
		env := envName(prefix, name)
		if env == "" {
			continue
		}
		value := values[name]

		switch format {
		case "sh":
			b.WriteString("export " + env + "=" + quoteSh(value) + "\n")
		case "powershell":
			b.WriteString("$env:" + env + " = " + quotePowerShell(value) + "\n")
		case "dotenv":
			b.WriteString(env + "=" + quoteDotenv(value) + "\n")
		default:
			return "", fmt.Errorf("format inconnu : %q (sh, powershell, dotenv ou json)", format)
		}
	}
	return b.String(), nil
}

// quoteSh wraps a value for a POSIX shell.
//
// Single quotes, where nothing at all is interpreted - no variable expansion,
// no backtick, no backslash. A single quote inside is closed, escaped and
// reopened, which is the only way to write one in that context.
func quoteSh(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// quotePowerShell does the same for PowerShell, where a single-quoted string
// is literal and an embedded quote is written twice.
func quotePowerShell(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}

// quoteDotenv writes a value the way the .env parsers agree on: double quotes,
// with the backslash, the quote and the newline escaped.
func quoteDotenv(v string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"\n", `\n`,
		"\r", `\r`,
	)
	return `"` + r.Replace(v) + `"`
}
