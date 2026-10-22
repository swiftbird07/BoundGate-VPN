package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
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
// repair`, the tray and the Mac app ask it to do the same thing.
func repairHost(cfgPath string) error {
	stateDir := defaults.stateDir
	if b, err := os.ReadFile(cfgPath); err == nil {
		if cfg, err := parseConfig(b); err == nil && cfg.StateDir != "" {
			stateDir = cfg.StateDir
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// the journal of the daemon, wherever its state is; with several
	// networks it is one for all of them, in the root of the state
	path := filepath.Join(stateDir, "netstate.json")
	rep, err := node.RepairHost(ctx, netcfg.NewJournal(netcfg.New(), path))
	if rep.Undone > 0 {
		fmt.Printf("undid %d network change(s) an earlier run recorded in %s\n", rep.Undone, path)
	}
	for _, k := range rep.Removed {
		fmt.Println("removed a resolver entry this host was left with:", k)
	}
	// An entry whose device is still there belongs to a node that is
	// running: a repair must not take it away, or it would break the
	// machine it is here to repair.
	for _, k := range rep.LeftAlone {
		fmt.Println("left alone, its tunnel device is still there (end that node with `boundgatectl down`):", k)
	}
	if err != nil {
		return err
	}
	fmt.Println(rep.Summary)
	if rep.Undone > 0 || len(rep.Removed) > 0 {
		fmt.Println("A node that is running now has its routes back on the next check (`boundgatectl status`).")
	}
	return nil
}
