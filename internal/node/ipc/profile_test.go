package ipc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
)

// POST /v1/profile reaches the node, and an unknown name is refused with a
// message instead of a 500.
func TestSetProfileOverTheSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "bgipc") // unix socket paths are short
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	n, err := node.New(node.Config{Name: "mac", StateDir: filepath.Join(dir, "state"),
		ControlAddr: "control.test:443", Roles: []string{"endpoint"}, Profile: "full"})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, sock, n, Options{}) }()
	c := NewClient(sock)
	for i := 0; ; i++ {
		if _, err = c.Status(); err == nil {
			break
		}
		if i > 50 {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// down: no session, so the choice is remembered for the next up
	if _, err := c.SetProfile("lan-only"); err != nil {
		t.Fatalf("lan-only: %v", err)
	}
	if _, err := c.SetProfile("nonsense"); err == nil {
		t.Fatal("an unknown profile was accepted")
	}
}
