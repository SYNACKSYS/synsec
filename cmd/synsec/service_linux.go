//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"synsec/internal/config"
)

const unitPath = "/etc/systemd/system/synsec.service"

// serviceModeRequested is always false on Linux: systemd runs SYNSEC as an
// ordinary process and stops it with SIGTERM, which serve already handles.
func serviceModeRequested() bool { return false }

func runServiceMode([]string) error { return errors.New("mode service inutilisé sur Linux") }

// unitTemplate is deliberately spare.
//
// The hardening directives are the ones that actually matter for a process
// holding decryption keys in memory: no new privileges, a private /tmp, and a
// read-only system apart from its own data directory.
const unitTemplate = `[Unit]
Description=SYNSEC - serveur de secrets
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s %s
Restart=always
RestartSec=5s

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=%s

[Install]
WantedBy=multi-user.target
`

// unitArgs renders the command line for the unit file.
//
// systemd splits ExecStart on whitespace, so a data directory with a space in
// it would silently become two arguments. Quoting the ones that need it is
// what keeps "/srv/mes secrets" a single path.
func unitArgs(cfg config.Config) string {
	args := serveArgs(cfg)
	for i, arg := range args {
		if strings.ContainsAny(arg, " 	\"") {
			args[i] = strconv.Quote(arg)
		}
	}
	return strings.Join(args, " ")
}

func installService(cfg config.Config) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("chemin de l'exécutable : %w", err)
	}

	unit := fmt.Sprintf(unitTemplate, exe, unitArgs(cfg), cfg.DataDir)

	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return errors.New("installation refusée : relance avec sudo\n" +
				"          sudo synsec service install")
		}
		return fmt.Errorf("écriture de %s : %w", unitPath, err)
	}

	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", "--now", "synsec.service"); err != nil {
		return err
	}
	return confirmRunning(exe)
}

// confirmRunning attend que le service soit vraiment parti.
//
// « systemctl enable --now » rend la main dès que systemd a accepté la
// demande, pas quand le programme tourne. Sans cette vérification,
// l'installation annonçait « installé et démarré » pendant que le service
// bouclait sur son propre démarrage - constaté sur une machine Ubuntu, où le
// message était faux et où rien ne le disait.
func confirmRunning(exe string) error {
	// Actif une fois ne suffit pas. Type=simple fait dire « active » à systemd
	// dès que le processus est lancé, et un service qui meurt aussitôt repasse
	// par « active » à chaque redémarrage : regarder une seule fois, au mauvais
	// instant, revient à confirmer une panne. On demande donc qu'il tienne.
	stable := 0
	for i := 0; i < 15; i++ {
		out, _ := exec.Command("systemctl", "is-active", "synsec.service").Output()
		if strings.TrimSpace(string(out)) == "active" {
			stable++
			if stable >= 4 {
				return nil
			}
		} else {
			stable = 0
		}
		time.Sleep(time.Second)
	}

	message := "le service a été installé mais ne démarre pas.\n" +
		"        Son journal dit pourquoi :  journalctl -u synsec.service -n 20"

	// La cause la plus probable, et la moins devinable. L'unité pose
	// ProtectHome, qui rend /home et /root inatteignables au service : un
	// binaire rangé là ne peut pas même être exécuté, et systemd répond
	// 203/EXEC sans autre explication.
	if strings.HasPrefix(exe, "/home/") || strings.HasPrefix(exe, "/root/") {
		message += "\n\n        Probable : l'exécutable est dans " + exe + ".\n" +
			"        L'unité interdit au service d'atteindre /home et /root.\n" +
			"        Déplace-le, puis réinstalle :\n" +
			"          sudo cp " + exe + " /usr/local/bin/synsec\n" +
			"          sudo /usr/local/bin/synsec service install"
	}
	return errors.New(message)
}

func uninstallService() error {
	// Failures here are tolerated: a unit that is already stopped or already
	// disabled must not turn removal into an error.
	_ = systemctl("disable", "--now", "synsec.service")

	if err := os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		if errors.Is(err, os.ErrPermission) {
			return errors.New("suppression refusée : relance avec sudo")
		}
		return fmt.Errorf("suppression de %s : %w", unitPath, err)
	}
	return systemctl("daemon-reload")
}

func serviceStatus() (string, error) {
	if _, err := os.Stat(unitPath); errors.Is(err, os.ErrNotExist) {
		return "Le service SYNSEC n'est pas installé.\n" +
			"Pour l'installer :  sudo synsec service install", nil
	}

	out, err := exec.Command("systemctl", "is-active", "synsec.service").Output()
	state := strings.TrimSpace(string(out))
	if state == "" {
		state = "inconnu"
	}
	// is-active exits non-zero when inactive, which is information, not a
	// failure to report.
	_ = err

	return fmt.Sprintf("Service SYNSEC : %s\nUnité : %s", state, unitPath), nil
}

func systemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl %s : %w\n        Détail : %s",
			strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}
