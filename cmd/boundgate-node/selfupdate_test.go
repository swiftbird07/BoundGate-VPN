package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
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
