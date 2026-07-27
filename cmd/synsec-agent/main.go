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

// Command synsec-agent fetches secrets from a SYNSEC server and hands them to
// a program through its environment.
//
// A binary of its own rather than a subcommand of synsec: this one runs on
// every machine that consumes a secret - a laptop, a Raspberry Pi, a container
// - and has no business carrying the database engine, the web interface and
// the encryption the server needs. It speaks HTTP and nothing else.
//
// Values never touch the disk and never reach a log. They live in the child
// process's environment and disappear with it.
package main

import (
	"fmt"
	"os"
	"strings"
)

var commands = map[string]func(args []string) error{
	"run":     runRun,
	"env":     runEnv,
	"get":     runGet,
	"list":    runList,
	"version": runVersion,
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "-h", "--help", "help":
		usage()
		return
	}

	run, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "synsec-agent : commande inconnue %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err := run(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "synsec-agent : %s\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, strings.TrimSpace(`
synsec-agent - injecte les secrets SYNSEC dans un programme

Utilisation :
  synsec-agent <commande> [options]

Commandes :
  run      Lance un programme avec les secrets dans son environnement
  env      Écrit les secrets sous forme d'affectations, à évaluer par le shell
  get      Écrit la valeur d'un secret sur la sortie standard
  list     Liste les secrets que ce jeton atteint, sans leurs valeurs
  version  Affiche la version de l'agent

Configuration, par variable d'environnement ou par option :
  SYNSEC_ADDR    https://ton-serveur:8787   (-addr)
  SYNSEC_TOKEN   syn_...                    (-token)
  SYNSEC_CA      chemin du certificat       (-ca)

Exemples :
  synsec-agent run -- python bot.py
  synsec-agent run -prefix APP_ -- ./mon-service
  eval "$(synsec-agent env)"
  synsec-agent get mot_de_passe_mqtt
`)+"\n")
}

func runVersion(args []string) error {
	fmt.Println("synsec-agent " + agentVersion)
	return nil
}

// agentVersion is stamped at build time with:
//
//	go build -ldflags "-X main.agentVersion=1.2.3" ./cmd/synsec-agent
var agentVersion = "dev"
