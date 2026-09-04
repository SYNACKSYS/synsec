//go:build linux

package main

import "synsec/internal/unseal"

// noChipAdvice dit quoi faire quand aucune puce n'est utilisable.
//
// Deux situations très différentes se cachent derrière « pas de TPM » : la
// machine n'en a pas, ou elle en a une que le système ne sait pas atteindre.
// Le second cas se règle avec un paquet, le premier avec un réglage de
// firmware ou une case cochée chez l'hyperviseur. Donner le second conseil à
// quelqu'un dans le premier cas l'envoie chercher ce qu'il a déjà.
func noChipAdvice() string {
	if manque := unseal.TPM2Missing(); manque != "" {
		return manque
	}
	return "Sur une machine virtuelle, ajoute un TPM virtuel dans sa " +
		"configuration ; sur du matériel, cherche fTPM ou PTT dans le " +
		"firmware. Vérifie ensuite avec « systemd-creds has-tpm2 », puis " +
		"« synsec maintenance sceller » déplace la clé sans rien réinstaller."
}
