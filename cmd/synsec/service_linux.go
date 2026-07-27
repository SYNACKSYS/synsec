//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

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
ExecStart=%s serve -data %s -listen %s
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

func installService(cfg config.Config) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("chemin de l'exécutable : %w", err)
	}

	unit := fmt.Sprintf(unitTemplate, exe, cfg.DataDir, cfg.Listen, cfg.DataDir)

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
	return systemctl("enable", "--now", "synsec.service")
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
