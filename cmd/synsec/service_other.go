//go:build !windows && !linux

package main

import (
	"errors"
	"runtime"

	"synsec/internal/config"
)

// SYNSEC targets Windows and Linux boxes on a home network. Elsewhere it runs
// perfectly well in the foreground; only the automatic-start integration is
// missing, and saying so plainly beats a half-working launchd file.

func serviceModeRequested() bool { return false }

func runServiceMode([]string) error { return errors.New("mode service non pris en charge") }

func installService(config.Config) error {
	return errors.New("installation en service non prise en charge sur " + runtime.GOOS +
		"\n        Lance SYNSEC au premier plan :  synsec serve")
}

func uninstallService() error {
	return errors.New("installation en service non prise en charge sur " + runtime.GOOS)
}

func serviceStatus() (string, error) {
	return "Installation en service non prise en charge sur " + runtime.GOOS + ".", nil
}
