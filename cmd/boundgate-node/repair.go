package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	j := netcfg.NewJournal(netcfg.New(), filepath.Join(stateDir, "netstate.json"))
	done := 0
	if n := j.Recover(ctx); n > 0 {
		fmt.Printf("undid %d network change(s) an earlier run recorded in %s\n", n, filepath.Join(stateDir, "netstate.json"))
		done += n
	}
	if s, ok := netcfg.Sweeper(j); ok {
		keys, err := s.SweepDNS(ctx)
		if err != nil {
			return fmt.Errorf("the host's resolver could not be given back: %w", err)
		}
		for _, k := range keys {
			fmt.Println("removed a resolver entry this host was left with:", k)
		}
		done += len(keys)
		// An entry whose device is still there belongs to a node that is
		// running: this must not take it away, or it would break the
		// machine it is here to repair.
		for _, k := range s.LiveDNSKeys(ctx) {
			fmt.Println("left alone, its tunnel device is still there (end that node with `boundgatectl down`):", k)
		}
	}
	if done == 0 {
		fmt.Println("nothing to undo: this host carries no network changes of a BoundGate node")
		return nil
	}
	fmt.Println("done. A node that is running now has its routes back on the next check (`boundgatectl status`).")
	return nil
}
