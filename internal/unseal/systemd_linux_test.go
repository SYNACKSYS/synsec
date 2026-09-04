//go:build linux

package unseal

import "strings"

import "testing"

// Le rapport de has-tpm2 tel qu'il sort vraiment, relevé sur un serveur
// Ubuntu 24.04 doté d'une puce TPM 2.0 dont il manquait un paquet.
const rapportBibliothequesManquantes = `partial
+firmware
+driver
+system
+subsystem
-libraries`

func TestUnePuceJoignableAQuiIlManqueUnPaquetLeDit(t *testing.T) {
	conseil := expliqueHasTPM2(rapportBibliothequesManquantes)

	if conseil == "" {
		t.Fatal("aucun conseil : la personne repart chercher une puce qu'elle a déjà")
	}
	if !strings.Contains(conseil, "libtss2") {
		t.Errorf("le conseil ne nomme pas le paquet à installer : %q", conseil)
	}
}

func TestUneMachineSansPuceGardeLeConseilGenerique(t *testing.T) {
	// Firmware absent : il n'y a réellement rien à joindre. Renvoyer un
	// conseil ici doublerait celui que l'appelant donne déjà.
	rapport := "partial\n-firmware\n-driver\n-system\n-subsystem\n-libraries"

	if conseil := expliqueHasTPM2(rapport); conseil != "" {
		t.Errorf("conseil inattendu sur une machine sans puce : %q", conseil)
	}
}

func TestUnPiloteAbsentEstDistingueDUnPaquetAbsent(t *testing.T) {
	rapport := "partial\n+firmware\n-driver\n-system\n-subsystem\n+libraries"

	conseil := expliqueHasTPM2(rapport)
	if !strings.Contains(conseil, "pilote") {
		t.Errorf("le pilote manquant n'est pas nommé : %q", conseil)
	}
	if strings.Contains(conseil, "libtss2") {
		t.Errorf("propose d'installer un paquet qui ne manque pas : %q", conseil)
	}
}
