package main

import (
	"strings"
	"testing"

	"synsec/internal/importer"
)

func entries(pairs ...string) []importer.Entry {
	var out []importer.Entry
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, importer.Entry{Key: pairs[i], Value: pairs[i+1], Line: i/2 + 1})
	}
	return out
}

// Running an import twice must not quietly write a second version of
// everything: the second run is usually a mistake, not an intent.
func TestPlanSkipsWhatAlreadyExists(t *testing.T) {
	taken := map[string]bool{"mqtt_password": true}
	plan, err := planImport(entries("mqtt_password", "a", "wifi_key", "b"), taken, false)
	if err != nil {
		t.Fatalf("planImport: %v", err)
	}

	if plan.toWrite() != 1 {
		t.Fatalf("%d entries would be written, want 1", plan.toWrite())
	}
	if !plan.items[0].skip {
		t.Error("the existing identifier is not skipped")
	}
	if plan.items[1].skip {
		t.Error("the new identifier is skipped")
	}
}

func TestReplaceOverwritesDeliberately(t *testing.T) {
	taken := map[string]bool{"mqtt_password": true}
	plan, err := planImport(entries("mqtt_password", "a"), taken, true)
	if err != nil {
		t.Fatalf("planImport: %v", err)
	}
	if plan.toWrite() != 1 || plan.items[0].skip {
		t.Fatal("-remplacer did not take effect")
	}
	if plan.items[0].reason != "remplacé" {
		t.Fatalf("the state reads %q", plan.items[0].reason)
	}
}

// Two keys can slugify to the same identifier. Letting one overwrite the other
// would lose a secret without saying so.
func TestCollidingKeysAreRefused(t *testing.T) {
	_, err := planImport(entries("mqtt-password", "a", "mqtt_password", "b"), nil, false)
	if err == nil {
		t.Fatal("two keys giving the same identifier were accepted")
	}
	if !strings.Contains(err.Error(), "mqtt_password") {
		t.Fatalf("the error does not name the identifier: %v", err)
	}
}

// A key made only of punctuation yields nothing addressable.
func TestKeyWithoutUsableIdentifierIsRefused(t *testing.T) {
	if _, err := planImport(entries("---", "a"), nil, false); err == nil {
		t.Fatal("a key with no usable identifier was accepted")
	}
}

// The label keeps the original key, so the interface shows what the file said
// while devices address the slug.
func TestOriginalKeyBecomesTheLabel(t *testing.T) {
	plan, err := planImport(entries("MQTT Password", "a"), nil, false)
	if err != nil {
		t.Fatalf("planImport: %v", err)
	}
	if plan.items[0].name != "mqtt_password" {
		t.Fatalf("the identifier is %q", plan.items[0].name)
	}
	if plan.items[0].entry.Key != "MQTT Password" {
		t.Fatalf("the original key was lost: %q", plan.items[0].entry.Key)
	}
}
