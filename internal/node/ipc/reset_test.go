package ipc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
)

// POST /v1/reset passes on whether a new identity was asked for, and an old
// client that sends no body asks for none.
func TestResetNewIdentity(t *testing.T) {
	for _, want := range []bool{false, true} {
		dir, err := os.MkdirTemp("/tmp", "bgipc") // unix socket paths are short
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		n, err := node.New(node.Config{Name: "mac", StateDir: filepath.Join(dir, "state"), ControlAddr: "control.test:443", Roles: []string{"endpoint"}})
		if err != nil {
			t.Fatal(err)
		}
		sock := filepath.Join(dir, "s")
		got := make(chan bool, 1)
		done := make(chan error, 1)
		go func() {
			done <- Serve(context.Background(), sock, n, Options{Reset: func(newIdentity bool) error { got <- newIdentity; return nil }})
		}()
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
		if err := c.Reset(want); err != nil {
			t.Fatal(err)
		}
		if v := <-got; v != want {
			t.Fatalf("new identity: got %v, want %v", v, want)
		}
		select {
		case err := <-done:
			if !errors.Is(err, ErrReset) {
				t.Fatalf("Serve returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not return after the reset")
		}
	}
}
