//go:build darwin

package netcfg

import (
	"context"
	"errors"
	"fmt"
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

// scutil runs its commands from stdin and returns what it printed.
func scutil(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "scutil")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
