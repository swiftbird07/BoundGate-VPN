package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
)

// With a daemon running, -repair asks it and leaves the journal alone: the
// journal is what the running session uses, and replaying it from outside
// took the routes and the NAT away from a node that is up.
func TestRepairAsksARunningDaemon(t *testing.T) {
	dir, err := os.MkdirTemp("", "bgr") // a short path: unix sockets have a length limit
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "n.sock")
	local := 0
	replay := func(context.Context, string) (node.RepairReport, error) {
		local++
		return node.RepairReport{Undone: 3, Summary: "Took back 3."}, nil
	}

	// no daemon: the journal is replayed here
	var out bytes.Buffer
	if err := runRepair(&out, sock, dir, replay); err != nil || local != 1 || !strings.Contains(out.String(), "undid 3") {
		t.Fatalf("without a daemon: err %v, replays %d, %q", err, local, out.String())
	}

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	asked := 0
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/repair" {
			asked++
			_ = json.NewEncoder(w).Encode(node.RepairReport{Reapplied: true, Summary: "Applied the routes again."})
			return
		}
		http.NotFound(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	out.Reset()
	if err := runRepair(&out, sock, dir, replay); err != nil {
		t.Fatal(err)
	}
	if local != 1 || asked != 1 || !strings.Contains(out.String(), "Applied the routes again.") {
		t.Fatalf("with a daemon: replays %d, asked %d, %q", local, asked, out.String())
	}
}
