// SYNSEC - serveur de secrets personnel.
// Copyright (C) 2026 Cyril Pineiro - SYNACKSYS
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Command synsec is the SYNSEC server and its administration tool, in one
// binary.
//
// One executable rather than two so that installing SYNSEC means copying a
// single file, and so that the administration commands can never drift out of
// step with the server they administer.
package main

import (
	"fmt"
	"os"
	"strings"
)

// commands maps a subcommand name to its implementation.
//
// Names are French because the people running this are French and the whole
// interface is; the English aliases exist so that documentation copied from
// anywhere else still works.
var commands = map[string]func(args []string) error{
	"init":        runInit,
	"serve":       runServe,
	"coffre":      runVault,
	"vault":       runVault,
	"secret":      runSecret,
	"token":       runToken,
	"utilisateur": runUser,
	"user":        runUser,
	"cert":        runCert,
	"service":     runService,
	"recover":     runRecover,
	"recuperer":   runRecover,
}

func main() {
	// Started by the service control manager there is no console, no user and
	// no argument list of our choosing: the process has to answer the service
	// protocol instead of behaving like a command.
	if serviceModeRequested() {
		if err := runServiceMode(os.Args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "synsec : %s\n", err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	name := os.Args[1]
	switch name {
	case "-h", "--help", "help":
		usage()
		return
	}

	run, ok := commands[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "synsec : commande inconnue %q\n\n", name)
		usage()
		os.Exit(2)
	}

	if err := run(os.Args[2:]); err != nil {
		// Errors reach a person, often a non-technical one, so they are
		// written plainly and without a stack trace.
		fmt.Fprintf(os.Stderr, "synsec : %s\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, strings.TrimSpace(`
SYNSEC - serveur de secrets personnel

Utilisation :
  synsec <commande> [options]

Commandes :
  init     Prépare le serveur : clé de chiffrement et code de récupération
  serve    Démarre le serveur
  coffre   Crée et liste les coffres
  secret   Enregistre, lit et supprime des secrets
  token    Connecte un appareil à un coffre

  utilisateur  Gère les comptes de l'interface web
  cert         Installe le certificat pour supprimer l'avertissement du navigateur
  service      Installe SYNSEC en service, pour un démarrage automatique
  recover      Rouvre le coffre avec le code de récupération imprimé

Aide d'une commande :
  synsec coffre -h
  synsec token -h

Pour commencer :
  synsec init
  synsec coffre create Maison
  synsec secret set Maison /mqtt/password
  synsec token create Maison "Home Assistant" -path /mqtt
  synsec serve
`)+"\n")
}
