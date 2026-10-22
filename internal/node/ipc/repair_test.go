package ipc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
)

// a host that carries nothing and would panic if anything were asked of it
type untouchedHost struct{ netcfg.Configurator }

// POST /v1/repair reaches the node, so that the tray and the Mac app have the
// way back a host needs when it resolves no names any more -- not only
// `boundgate-node -repair` in a shell (R144).
func TestRepairOverTheSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "bgipc") // unix socket paths are short
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	n, err := node.New(node.Config{Name: "mac", StateDir: filepath.Join(dir, "state"),
		ControlAddr: "control.test:443", Roles: []string{"endpoint"}, Net: untouchedHost{}})
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
	rep, err := c.Repair()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rep.Summary, "Nothing to repair") {
		t.Errorf("summary %q", rep.Summary)
	}
	if rep.Undone != 0 || len(rep.Removed) != 0 {
		t.Errorf("a host that carries nothing had something undone: %+v", rep)
	}
}
