//go:build !windows

package main

import "os"

// Les droits, hors de Windows.
//
// Écrit après avoir vu l'installation annoncer « Fenêtre : administrateur »
// sur une machine Ubuntu où rien n'avait été vérifié. Une ligne fausse dans un
// écran qui parle de protection coûte plus cher que pas de ligne du tout.
//
// Root est demandé pour de vraies raisons ici : écrire dans /var/lib/synsec,
// installer une unité systemd, et parler au TPM par systemd-creds, qui a
// besoin d'atteindre /dev/tpmrm0.

func isElevated() bool { return os.Geteuid() == 0 }

func elevationHint() string {
	if isElevated() {
		return ""
	}
	return "Cette commande a besoin des droits du système : le dossier de " +
		"données, l'unité systemd et l'accès à la puce en dépendent. " +
		"Relance-la avec sudo."
}
