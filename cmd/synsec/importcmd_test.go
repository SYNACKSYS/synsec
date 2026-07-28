package main

import (
	"strings"
	"testing"

	"synsec/internal/importer"
	"synsec/internal/store"
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
	plan, err := importer.BuildPlan(entries("mqtt_password", "a", "wifi_key", "b"), taken, false, store.Slugify)
	if err != nil {
		t.Fatalf("planImport: %v", err)
	}

	if plan.ToWrite() != 1 {
		t.Fatalf("%d entries would be written, want 1", plan.ToWrite())
	}
	if !plan.Items[0].Skip {
		t.Error("the existing identifier is not skipped")
	}
	if plan.Items[1].Skip {
		t.Error("the new identifier is skipped")
	}
}

func TestReplaceOverwritesDeliberately(t *testing.T) {
	taken := map[string]bool{"mqtt_password": true}
	plan, err := importer.BuildPlan(entries("mqtt_password", "a"), taken, true, store.Slugify)
	if err != nil {
		t.Fatalf("planImport: %v", err)
	}
	if plan.ToWrite() != 1 || plan.Items[0].Skip {
		t.Fatal("-remplacer did not take effect")
	}
	if plan.Items[0].Reason != "remplacé" {
		t.Fatalf("the state reads %q", plan.Items[0].Reason)
	}
}

// Two keys can slugify to the same identifier. Letting one overwrite the other
// would lose a secret without saying so.
func TestCollidingKeysAreRefused(t *testing.T) {
	_, err := importer.BuildPlan(entries("mqtt-password", "a", "mqtt_password", "b"), nil, false, store.Slugify)
	if err == nil {
		t.Fatal("two keys giving the same identifier were accepted")
	}
	if !strings.Contains(err.Error(), "mqtt_password") {
		t.Fatalf("the error does not name the identifier: %v", err)
	}
}

// A key made only of punctuation yields nothing addressable.
func TestKeyWithoutUsableIdentifierIsRefused(t *testing.T) {
	if _, err := importer.BuildPlan(entries("---", "a"), nil, false, store.Slugify); err == nil {
		t.Fatal("a key with no usable identifier was accepted")
	}
}

// The label keeps the original key, so the interface shows what the file said
// while devices address the slug.
func TestOriginalKeyBecomesTheLabel(t *testing.T) {
	plan, err := importer.BuildPlan(entries("MQTT Password", "a"), nil, false, store.Slugify)
	if err != nil {
		t.Fatalf("planImport: %v", err)
	}
	if plan.Items[0].Name != "mqtt_password" {
		t.Fatalf("the identifier is %q", plan.Items[0].Name)
	}
	if plan.Items[0].Entry.Key != "MQTT Password" {
		t.Fatalf("the original key was lost: %q", plan.Items[0].Entry.Key)
	}
}
