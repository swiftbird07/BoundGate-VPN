package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A replaced executable ends the daemon (SIGTERM to itself), but only while
// the node is idle.
func TestRestartWhenReplaced(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	defer signal.Stop(sig)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var idle atomic.Bool
	go restartWhenReplaced(ctx, slog.New(slog.DiscardHandler), idle.Load, 10*time.Millisecond)

	select {
	case <-sig:
		t.Fatal("restarted although nothing changed")
	case <-time.After(100 * time.Millisecond):
	}
	// "replace" the test binary: same content, new modification time
	if err := os.Chtimes(exe, time.Now(), time.Now().Add(time.Minute)); err != nil {
		t.Skip("cannot touch the test binary:", err)
	}
	select {
	case <-sig:
		t.Fatal("restarted while the node was up")
	case <-time.After(100 * time.Millisecond):
	}
	idle.Store(true)
	select {
	case <-sig:
	case <-time.After(2 * time.Second):
		t.Fatal("no restart after the executable changed")
	}
}

// A daemon that ended for its own update leaves the profile it was connected
// in; the next start connects in it once. An old record is not the update's.
func TestResumeAfterUpdate(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.DiscardHandler)
	if got := takeResume(dir, log); got != "" {
		t.Fatalf("nothing recorded, yet %q", got)
	}
	if err := saveResume(dir, "lan-only"); err != nil {
		t.Fatal(err)
	}
	if got := takeResume(dir, log); got != "lan-only" {
		t.Fatalf("got %q", got)
	}
	if got := takeResume(dir, log); got != "" {
		t.Fatalf("a record was used twice: %q", got)
	}
	// a node that named no profile comes up in the full one
	if err := saveResume(dir, ""); err != nil {
		t.Fatal(err)
	}
	if got := takeResume(dir, log); got != "full" {
		t.Fatalf("got %q", got)
	}
	// a daemon started by hand long after a failed update does not connect
	if err := saveResume(dir, "full"); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(dir, resumeFile), old, old); err != nil {
		t.Fatal(err)
	}
	if got := takeResume(dir, log); got != "" {
		t.Fatalf("an hour-old record connected: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, resumeFile)); err == nil {
		t.Fatal("the old record was left behind")
	}
}
