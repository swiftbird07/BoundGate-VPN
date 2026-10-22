//go:build darwin

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

// ErrNoResolver says this Mac did not take the resolver setting. The node
// keeps the system's resolver and reports it; it is not a reason to refuse
// the overlay.
var ErrNoResolver = errors.New("netcfg: the system configuration did not take the resolver")

// SetLinkDNS implements LinkDNSConfigurator: while the overlay is up this
// Mac asks the hub's resolvers for every name, and when it goes down it asks
// its own again. darwinDNSScript says how and why.
func (darwinCfg) SetLinkDNS(ctx context.Context, ifname string, servers []netip.Addr) error {
	script, err := darwinDNSScript(ifname, servers)
	if err != nil {
		return err
	}
	out, err := scutil(ctx, script)
	switch {
	case err != nil:
		return fmt.Errorf("%w: %v: %s", ErrNoResolver, err, out)
	// scutil reports a refused write on stdout and still exits 0; a
	// "remove" of a key that is not there says "No such key", which is
	// what teardown wants to hear
	case len(servers) > 0 && strings.Contains(out, "failed"):
		return fmt.Errorf("%w: %s", ErrNoResolver, out)
	}
	return nil
}

// SweepDNS implements DNSSweeper: it removes the resolver entries a node of
// ours left in the system configuration **for devices that are gone**,
// whether or not a journal still knows about them. That is what gets a Mac
// whose daemon died mid-teardown its names back, without a reboot.
//
// An entry whose tunnel device still exists belongs to a node that is very
// probably running -- another one on this machine, a lab node beside the
// installed daemon -- and taking its resolver away would break exactly what
// this is meant to repair. Those are left alone and named, so the caller can
// say that `boundgatectl down` is the way to end a node that is still there.
func (darwinCfg) SweepDNS(ctx context.Context) ([]string, error) {
	out, err := scutil(ctx, darwinDNSListScript)
	if err != nil {
		return nil, fmt.Errorf("netcfg: asking the system configuration for leftovers: %v: %s", err, out)
	}
	var stale []string
	for _, k := range darwinDNSKeys(out) {
		ifname := darwinDNSIface(k)
		if ifname == "" {
			continue
		}
		if _, err := net.InterfaceByName(ifname); err == nil {
			continue // the device is still there, so someone still owns this
		}
		stale = append(stale, k)
	}
	if len(stale) == 0 {
		return nil, nil
	}
	if out, err := scutil(ctx, darwinDNSRemoveScript(stale)); err != nil {
		return nil, fmt.Errorf("%w: %v: %s", ErrNoResolver, err, out)
	}
	return stale, nil
}

// LiveDNSKeys are the resolver entries of ours whose device still exists:
// nodes that are still running, which a repair must not touch.
func (darwinCfg) LiveDNSKeys(ctx context.Context) []string {
	out, err := scutil(ctx, darwinDNSListScript)
	if err != nil {
		return nil
	}
	var live []string
	for _, k := range darwinDNSKeys(out) {
		if ifname := darwinDNSIface(k); ifname != "" {
			if _, err := net.InterfaceByName(ifname); err == nil {
				live = append(live, k)
			}
		}
	}
	return live
}

// scutil runs its commands from stdin and returns what it printed.
func scutil(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "scutil")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
