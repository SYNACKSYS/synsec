package importer

import (
	"strings"
	"testing"
)

func parse(t *testing.T, format, body string) []Entry {
	t.Helper()
	entries, err := Parse(strings.NewReader(body), format)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return entries
}

func TestDetectFormat(t *testing.T) {
	cases := map[string]string{
		"secrets.yaml": FormatYAML,
		"SECRETS.YML":  FormatYAML,
		".env":         FormatEnv,
		"prod.env":     FormatEnv,
		"quelconque":   FormatEnv,
	}
	for name, want := range cases {
		if got := DetectFormat(name); got != want {
			t.Errorf("DetectFormat(%q) = %q, want %q", name, got, want)
		}
	}
}

// A real Home Assistant secrets.yaml, comments and quoting included.
func TestParseHomeAssistantSecrets(t *testing.T) {
	entries := parse(t, FormatYAML, `
# Ne jamais partager ce fichier
mqtt_password: s3cr3t
wifi_ssid: "Livebox-1234"
zigbee_key: 'a1b2c3'

ha_token: eyJhbGciOiJIUzI1NiJ9.abc
`)

	want := map[string]string{
		"mqtt_password": "s3cr3t",
		"wifi_ssid":     "Livebox-1234",
		"zigbee_key":    "a1b2c3",
		"ha_token":      "eyJhbGciOiJIUzI1NiJ9.abc",
	}
	if len(entries) != len(want) {
		t.Fatalf("%d entries read, want %d", len(entries), len(want))
	}
	for _, e := range entries {
		if want[e.Key] != e.Value {
			t.Errorf("%s = %q, want %q", e.Key, e.Value, want[e.Key])
		}
	}
}

func TestParseEnv(t *testing.T) {
	entries := parse(t, FormatEnv, `
# base
DB_PASSWORD=hunter2
export API_KEY="abc def"
EMPTY=
QUOTED='simple'
ESCAPED="ligne1\nligne2"
`)

	want := map[string]string{
		"DB_PASSWORD": "hunter2",
		"API_KEY":     "abc def",
		"EMPTY":       "",
		"QUOTED":      "simple",
		"ESCAPED":     "ligne1\nligne2",
	}
	if len(entries) != len(want) {
		t.Fatalf("%d entries read, want %d", len(entries), len(want))
	}
	for _, e := range entries {
		if want[e.Key] != e.Value {
			t.Errorf("%s = %q, want %q", e.Key, e.Value, want[e.Key])
		}
	}
}

// A password containing a hash must survive. Stripping inline comments would
// truncate it silently, and the failure would surface weeks later on a device.
func TestHashInAValueIsKept(t *testing.T) {
	entries := parse(t, FormatEnv, "PASSWORD=abc#def\n")
	if entries[0].Value != "abc#def" {
		t.Fatalf("the value is %q, want abc#def", entries[0].Value)
	}

	entries = parse(t, FormatYAML, "password: abc#def\n")
	if entries[0].Value != "abc#def" {
		t.Fatalf("the value is %q, want abc#def", entries[0].Value)
	}
}

// A nested file is the wrong file. Flattening it would invent names for its
// branches and create secrets nobody asked for.
func TestNestedYAMLIsRefused(t *testing.T) {
	_, err := Parse(strings.NewReader("mqtt:\n  password: s3cr3t\n"), FormatYAML)
	if err == nil {
		t.Fatal("a nested file was accepted")
	}
	if !strings.Contains(err.Error(), "imbriqu") {
		t.Fatalf("the error does not explain the nesting: %v", err)
	}
	// Reported at line 1, where the nesting opens, rather than at the indented
	// line that merely follows from it.
	if !strings.Contains(err.Error(), "ligne 1") {
		t.Fatalf("the error does not name the line: %v", err)
	}

	// And an indented line reached on its own is caught too.
	if _, err := Parse(strings.NewReader("a: 1\n  b: 2\n"), FormatYAML); err == nil {
		t.Fatal("an indented line was accepted")
	}
}

// A duplicate key means one of the two values would be lost without a word.
func TestDuplicateKeyIsRefused(t *testing.T) {
	for _, tc := range []struct{ format, body string }{
		{FormatYAML, "a: 1\nb: 2\na: 3\n"},
		{FormatEnv, "A=1\nB=2\nA=3\n"},
	} {
		_, err := Parse(strings.NewReader(tc.body), tc.format)
		if err == nil {
			t.Fatalf("%s: a duplicate key was accepted", tc.format)
		}
		if !strings.Contains(err.Error(), "ligne 3") || !strings.Contains(err.Error(), "ligne 1") {
			t.Errorf("%s: the error names neither line: %v", tc.format, err)
		}
	}
}

func TestMalformedLinesAreNamed(t *testing.T) {
	cases := map[string]struct{ format, body string }{
		"yaml sans deux-points": {FormatYAML, "mqtt_password\n"},
		"yaml sans valeur":      {FormatYAML, "mqtt_password:\n"},
		"yaml liste":            {FormatYAML, "- un\n"},
		"env sans egal":         {FormatEnv, "MQTT_PASSWORD\n"},
		"env clé vide":          {FormatEnv, "=valeur\n"},
	}
	for name, tc := range cases {
		_, err := Parse(strings.NewReader(tc.body), tc.format)
		if err == nil {
			t.Errorf("%s : accepté", name)
			continue
		}
		if !strings.Contains(err.Error(), "ligne 1") {
			t.Errorf("%s : l'erreur ne nomme pas la ligne : %v", name, err)
		}
	}
}

// The line number has to survive comments and blank lines, or it points at
// nothing useful.
func TestLineNumbersAreAccurate(t *testing.T) {
	entries := parse(t, FormatYAML, "# un commentaire\n\nmqtt: s3cr3t\n")
	if entries[0].Line != 3 {
		t.Fatalf("the entry is reported at line %d, want 3", entries[0].Line)
	}
}

// Notepad and PowerShell's Out-File both write a byte-order mark. Without
// stripping it, the first line of any file written on Windows is unreadable:
// a leading "#" stops being a comment, and a key gains three invisible bytes.
func TestByteOrderMarkIsIgnored(t *testing.T) {
	const bom = "\ufeff"

	entries := parse(t, FormatYAML, bom+"# commentaire\nmqtt: s3cr3t\n")
	if len(entries) != 1 || entries[0].Key != "mqtt" {
		t.Fatalf("the BOM broke the YAML parse: %+v", entries)
	}

	entries = parse(t, FormatEnv, bom+"MQTT=s3cr3t\n")
	if len(entries) != 1 || entries[0].Key != "MQTT" {
		t.Fatalf("the BOM broke the env parse: %+v", entries)
	}
}
