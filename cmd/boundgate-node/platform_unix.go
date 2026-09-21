//go:build !windows

package main

import (
	"context"
	"os/signal"
	"syscall"
)

var defaults = struct{ config, stateDir, profilesDir, logDir string }{
	config: "/etc/boundgate/node.yaml", stateDir: "/var/lib/boundgate", profilesDir: "/etc/boundgate/profiles",
}

// serviceCommand handles the service subcommands of Windows; there are none here.
func serviceCommand([]string) (bool, error) { return false, nil }

func runMain(cfgPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return run(ctx, cfgPath)
}

// terminateSelf ends the daemon the way its supervisor does (launchd, systemd).
func terminateSelf() { _ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM) }
