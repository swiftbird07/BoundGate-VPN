package main

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// underLaunchd reports whether launchd started this process (and, with
// KeepAlive, starts it again when it exits).
func underLaunchd() bool {
	name := os.Getenv("XPC_SERVICE_NAME")
	return name != "" && name != "0"
}

// restartWhenReplaced ends the daemon once its executable on disk is no
// longer the file it was started from and the node is idle. Replacing
// BoundGate.app does not restart its LaunchDaemon: the old process runs on
// from the deleted file, and the new app talks to an old daemon (which is how
// a Mac kept its software key through `reset -new-identity`). launchd starts
// the new binary right away. A node that is up is left alone until it is down.
func restartWhenReplaced(ctx context.Context, log *slog.Logger, idle func() bool, every time.Duration) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	started, err := os.Stat(exe)
	if err != nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now, err := os.Stat(exe)
		if err != nil || !now.Mode().IsRegular() {
			continue // mid-copy; look again
		}
		if os.SameFile(started, now) && now.ModTime().Equal(started.ModTime()) && now.Size() == started.Size() {
			continue
		}
		if !idle() {
			continue
		}
		log.Warn("this daemon's executable was replaced (app update); exiting so that launchd starts the new one", "path", exe)
		terminateSelf()
		return
	}
}
