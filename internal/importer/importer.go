// Package importer reads the files people already keep their secrets in.
//
// Two formats, both flat: the secrets.yaml of Home Assistant and the .env of
// everything else. Neither is parsed with a library. A dependency would be a
// poor trade for a file shaped like "key: value", and it would land in the
// one place where SYNSEC promises to have none.
//
// The subset is deliberately narrow, and what it does not understand it
// refuses by name and by line rather than guessing. A secret imported wrong is
// worse than one not imported: it fails later, on a device, at a moment nobody
// connects to the import that caused it.
package importer

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Formats understood.
const (
	FormatEnv  = "env"
	FormatYAML = "yaml"
)

// Entry is one key and its value, with the line it came from so an error can
// point at it.
type Entry struct {
	Key   string
	Value string
	Line  int
}

// DetectFormat guesses from the file name. Anything that is not clearly YAML
// is treated as an env file, which is the more forgiving of the two.
func DetectFormat(filename string) string {
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
		return FormatYAML
	}
	return FormatEnv
}

// Parse reads every entry in the file.
func Parse(r io.Reader, format string) ([]Entry, error) {
	switch format {
	case FormatYAML:
		return parseYAML(r)
	case FormatEnv:
		return parseEnv(r)
	default:
		return nil, fmt.Errorf("importer: format inconnu %q", format)
	}
}

// parseEnv reads KEY=VALUE, with the usual conveniences.
func parseEnv(r io.Reader) ([]Entry, error) {
	var out []Entry
	seen := make(map[string]int)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	for line := 1; scanner.Scan(); line++ {
		raw := strings.TrimSpace(dropBOM(scanner.Text(), line))
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		// "export FOO=bar" is how half the .env files in the wild are written.
		raw = strings.TrimPrefix(raw, "export ")

		key, value, found := strings.Cut(raw, "=")
		if !found {
			return nil, fmt.Errorf("ligne %d : ni « clé=valeur » ni un commentaire", line)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("ligne %d : la clé est vide", line)
		}
		if first, dup := seen[key]; dup {
			return nil, fmt.Errorf("ligne %d : « %s » apparaît déjà ligne %d", line, key, first)
		}
		seen[key] = line

		out = append(out, Entry{Key: key, Value: unquote(value), Line: line})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("lecture : %w", err)
	}
	return out, nil
}

// parseYAML reads the flat "key: value" subset that a secrets.yaml is.
//
// Anything nested is refused rather than flattened. Home Assistant's secrets
// file is flat by design; a nested one means the wrong file was given, and
// inventing names for its branches would create secrets nobody asked for.
func parseYAML(r io.Reader) ([]Entry, error) {
	var out []Entry
	seen := make(map[string]int)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	for line := 1; scanner.Scan(); line++ {
		raw := dropBOM(scanner.Text(), line)
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "---" {
			continue
		}
		if raw != strings.TrimLeft(raw, " \t") {
			return nil, fmt.Errorf(
				"ligne %d : ce fichier a des niveaux imbriqués, SYNSEC ne lit qu'une liste plate « clé: valeur »", line)
		}
		if strings.HasPrefix(trimmed, "- ") {
			return nil, fmt.Errorf("ligne %d : les listes ne sont pas gérées", line)
		}

		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			return nil, fmt.Errorf("ligne %d : ni « clé: valeur » ni un commentaire", line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			return nil, fmt.Errorf("ligne %d : la clé est vide", line)
		}
		// A key with nothing after the colon is how a nested block opens. Say
		// so, rather than reporting a missing value: the reader's problem is
		// the shape of the file, not that one line lacks something.
		if value == "" {
			return nil, fmt.Errorf(
				"ligne %d : « %s » n'a pas de valeur sur sa ligne, le fichier a donc des niveaux imbriqués ; "+
					"SYNSEC ne lit qu'une liste plate « clé: valeur »", line, key)
		}
		if first, dup := seen[key]; dup {
			return nil, fmt.Errorf("ligne %d : « %s » apparaît déjà ligne %d", line, key, first)
		}
		seen[key] = line

		out = append(out, Entry{Key: key, Value: unquote(value), Line: line})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("lecture : %w", err)
	}
	return out, nil
}

// dropBOM removes the byte-order mark Windows editors put at the head of a
// file.
//
// Notepad writes one, and so does PowerShell's Out-File. Without this, the
// first line of a file written on Windows is never recognised: a leading "#"
// stops being a comment and a key gains three invisible bytes, for a failure
// that names line 1 and explains nothing.
func dropBOM(s string, line int) string {
	if line == 1 {
		return strings.TrimPrefix(s, "\ufeff")
	}
	return s
}

// maxLineBytes bounds a single line. A secret is a password or a key, and a
// megabyte of one line means the wrong file was handed over.
const maxLineBytes = 1 << 20

// unquote strips one layer of quotes and undoes the escapes that a
// double-quoted value may carry.
//
// An inline comment is deliberately not stripped from an unquoted value. Doing
// so would silently truncate any password containing a hash, and a value that
// visibly carries a stray comment is a problem the preview shows, where a
// truncated password is one that surfaces weeks later on a device.
func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) < 2 {
		return v
	}

	switch {
	case v[0] == '\'' && v[len(v)-1] == '\'':
		return v[1 : len(v)-1]
	case v[0] == '"' && v[len(v)-1] == '"':
		inner := v[1 : len(v)-1]
		return strings.NewReplacer(
			`\n`, "\n",
			`\r`, "\r",
			`\t`, "\t",
			`\"`, `"`,
			`\\`, `\`,
		).Replace(inner)
	default:
		return v
	}
}
