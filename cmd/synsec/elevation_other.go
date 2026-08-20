//go:build !windows

package main

// Sur Linux, sceller dans le TPM passe par systemd-creds, qui échoue avec un
// message parlant quand les droits manquent. Rien à deviner ici.

func isElevated() bool { return true }

func elevationHint() string { return "" }
