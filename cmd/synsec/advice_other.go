//go:build !windows && !linux

package main

// noChipAdvice dit quoi faire quand aucune puce n'est utilisable.
//
// Conseil séparé de celui de Windows après l'avoir lu sur une machine
// virtuelle Ubuntu, où il envoyait chercher un réglage de BIOS qui n'existe
// pas. Sur une machine virtuelle, la puce s'ajoute côté hyperviseur ; sur du
// matériel, c'est bien le firmware.
func noChipAdvice() string {
	return "Sur une machine virtuelle, ajoute un TPM virtuel dans sa " +
		"configuration ; sur du matériel, cherche fTPM ou PTT dans le " +
		"firmware. Vérifie ensuite avec « systemd-creds has-tpm2 », puis " +
		"« synsec maintenance sceller » déplace la clé sans rien réinstaller."
}
