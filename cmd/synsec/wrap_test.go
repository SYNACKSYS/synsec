package main

import (
	"strings"
	"testing"
)

func TestUnGuillemetFermantNeCommencePasUneLigne(t *testing.T) {
	// Largeur choisie pour que la coupure tombe pile devant le guillemet
	// fermant : c'est le cas relevé à l'installation sur une machine Linux.
	texte := "Ensuite « synsec maintenance sceller » déplace la clé."

	for _, ligne := range strings.Split(wrap(texte, 20, ""), "\n") {
		if strings.HasPrefix(ligne, "»") {
			t.Errorf("guillemet fermant seul en début de ligne : %q", ligne)
		}
		if strings.HasSuffix(ligne, "«") {
			t.Errorf("guillemet ouvrant seul en fin de ligne : %q", ligne)
		}
	}
}

func TestLeTexteSurvitAuDecoupage(t *testing.T) {
	texte := "La puce est présente et son pilote est chargé, « voir has-tpm2 »."

	rendu := strings.Join(strings.Fields(wrap(texte, 24, "")), " ")
	if rendu != texte {
		t.Errorf("le découpage a modifié le texte :\n  avant : %q\n  après : %q", texte, rendu)
	}
}
