//go:build windows

package main

// noChipAdvice dit quoi faire quand aucune puce n'est utilisable.
//
// Le cas le plus fréquent n'est pas une machine sans puce : c'est une machine
// dont la puce dort dans le firmware, désactivée en usine.
func noChipAdvice() string {
	return "Beaucoup de cartes ont une puce désactivée en usine : cherche " +
		"fTPM (AMD) ou PTT (Intel) dans le BIOS. Une fois activée, " +
		"« synsec maintenance sceller » déplace la clé sans rien réinstaller."
}
