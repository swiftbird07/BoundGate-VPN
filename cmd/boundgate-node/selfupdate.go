package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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

// resumeFile names the profile a daemon was connected in when it ended for an
// update it had installed itself. The daemon that starts next reads it once.
const resumeFile = "resume-after-update"

// saveResume records profile for the next start.
func saveResume(stateDir, profile string) error {
	if profile == "" {
		profile = "full" // what a node that names no profile comes up in
	}
	return os.WriteFile(filepath.Join(stateDir, resumeFile), []byte(profile+"\n"), 0o600)
}

// takeResume returns the recorded profile and removes the record: it is good
// for the one start right after the update. A record older than a few
// minutes is not from that start -- a daemon that failed to come back and was
// started by hand a day later should not connect on its own -- and is dropped.
func takeResume(stateDir string, log *slog.Logger) string {
	p := filepath.Join(stateDir, resumeFile)
	fi, err := os.Lstat(p)
	if err != nil {
		return ""
	}
	defer os.Remove(p)
	if !fi.Mode().IsRegular() || fi.Size() > 256 || time.Since(fi.ModTime()) > resumeWithin {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	profile := strings.TrimSpace(string(b))
	log.Info("connecting again after the update", "profile", profile)
	return profile
}

// resumeWithin is how old a record may be and still be the update's.
const resumeWithin = 5 * time.Minute
