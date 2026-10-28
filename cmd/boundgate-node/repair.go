package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/ipc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
)

// repairHost undoes what a daemon that is no longer running left on this
// host's network: the resolver first, then routes, bypass routes and NAT.
//
// It exists because the normal way back -- `boundgatectl down`, or the next
// start of the daemon replaying its journal -- needs a daemon, and the one
// change that cannot wait for one is the resolver: while this host is pointed
// at a resolver inside a tunnel that is gone, nothing on the machine resolves
// a name, and on macOS that is true until the entry is removed or the machine
// is rebooted (docs/SECURITY.md R144). So this runs without a daemon, takes
// the journal if there is one, and sweeps the host's own configuration as
// well in case the daemon was killed before it could write the record.
//
// With a daemon running there is no need for a shell at all: `boundgatectl
// repair`, the tray and the Mac app ask it to do the same thing -- and so
// does this, when it finds one (runRepair).
func repairHost(cfgPath string) error {
	stateDir, sock := defaults.stateDir, ipc.DefaultSocket()
	if b, err := os.ReadFile(cfgPath); err == nil {
		if cfg, err := parseConfig(b); err == nil {
			if cfg.StateDir != "" {
				stateDir = cfg.StateDir
			}
			if cfg.Socket != "" {
				sock = cfg.Socket
			}
		}
	}
	return runRepair(os.Stdout, sock, stateDir, func(ctx context.Context, path string) (node.RepairReport, error) {
		return node.RepairHost(ctx, netcfg.NewJournal(netcfg.New(), path))
	})
}

// runRepair asks a daemon that is running, and only without one replays the
// journal itself. The journal of a running daemon is what its session uses:
// replayed from outside, it would take the routes, the NAT and the resolver
// away from a node that is up (only the resolver sweep looked at whether a
// device is still there). The daemon knows what is its own (Node.Repair).
func runRepair(out io.Writer, sock, stateDir string, local func(context.Context, string) (node.RepairReport, error)) error {
	if c, err := net.DialTimeout("unix", sock, 2*time.Second); err == nil {
		_ = c.Close()
		fmt.Fprintln(out, "a node daemon is running; asking it to repair, as `boundgatectl repair` does")
		rep, err := ipc.NewClient(sock).Repair()
		if err != nil {
			return fmt.Errorf("the running daemon did not repair: %w (stop it, then run -repair again)", err)
		}
		printRepair(out, rep, "")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// the journal of the daemon, wherever its state is; with several
	// networks it is one for all of them, in the root of the state
	path := filepath.Join(stateDir, "netstate.json")
	rep, err := local(ctx, path)
	printRepair(out, rep, path)
	return err
}

func printRepair(out io.Writer, rep node.RepairReport, path string) {
	if rep.Undone > 0 {
		fmt.Fprintf(out, "undid %d network change(s) an earlier run recorded in %s\n", rep.Undone, path)
	}
	for _, k := range rep.Removed {
		fmt.Fprintln(out, "removed a resolver entry this host was left with:", k)
	}
	// An entry whose device is still there belongs to a node that is
	// running: a repair must not take it away, or it would break the
	// machine it is here to repair.
	for _, k := range rep.LeftAlone {
		fmt.Fprintln(out, "left alone, its tunnel device is still there (end that node with `boundgatectl down`):", k)
	}
	if rep.Summary == "" {
		return // failed before it could say
	}
	fmt.Fprintln(out, rep.Summary)
	if path != "" && (rep.Undone > 0 || len(rep.Removed) > 0) {
		fmt.Fprintln(out, "A node that is running now has its routes back on the next check (`boundgatectl status`).")
	}
}
