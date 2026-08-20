//go:build windows

package main

import "golang.org/x/sys/windows"

// Savoir si on est en administrateur, et à quoi ça sert.
//
// Créer une clé dans le TPM demande une invite élevée. Sans elle, CNG répond
// NTE_PERM, l'installation retombe sur DPAPI, et tout se passe bien - sauf que
// le propriétaire vient de perdre la seule protection qui survit au vol du
// disque, sans que rien ne le lui dise.
//
// C'est exactement le repli silencieux que le reste du projet refuse. On le
// nomme donc avant qu'il arrive.

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// elevationHint est ce qu'on ajoute quand la protection obtenue est moins
// bonne que celle que la machine sait offrir.
func elevationHint() string {
	if isElevated() {
		return ""
	}
	return "Cette fenêtre n'est pas administrateur : la création d'une clé " +
		"dans la puce en a besoin. Relance la commande dans une invite " +
		"ouverte avec « Exécuter en tant qu'administrateur »."
}
