//go:build darwin

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

type darwinCfg struct{ own *ownIfaces }

// New returns the macOS configurator: utun through the wireguard tun
// package, ifconfig(8) and route(8) for the rest. macOS nodes are endpoints;
// forwarding and NAT (subnet router, hub) are not implemented.
func New() Configurator { return darwinCfg{own: &ownIfaces{}} }

func (c darwinCfg) CreateTUN(name string, mtu int) (tun.Device, string, error) {
	dev, err := tun.CreateTUN(darwinTUNName(name), mtu)
	if err != nil {
		return nil, "", fmt.Errorf("netcfg: create utun (needs root): %w", err)
	}
	n, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, "", err
	}
	c.own.add(n)
	return dev, n, nil
}

func (darwinCfg) SetAddress(ctx context.Context, ifname string, addr netip.Prefix, mtu int) error {
	return run(ctx, darwinAddrArgs(ifname, addr, mtu)...)
}

func (darwinCfg) AddRoute(ctx context.Context, dst netip.Prefix, ifname string) error {
	err := run(ctx, darwinRouteArgs("add", dst, ifname)...)
	if err != nil && strings.Contains(err.Error(), "File exists") {
		return run(ctx, darwinRouteArgs("change", dst, ifname)...)
	}
	return err
}

func (darwinCfg) DelRoute(ctx context.Context, dst netip.Prefix, ifname string) error {
	return run(ctx, darwinRouteArgs("delete", dst, ifname)...)
}

func (c darwinCfg) AddBypass(ctx context.Context, host netip.Addr) error {
	r, err := darwinRouteGet(ctx, host, host.String())
	if err != nil {
		return err
	}
	// Under a full-tunnel profile the node's own utun answers for every
	// address, also for a hub whose host route is being renewed after a
	// network change: the way out is then the default route, which the
	// profile's /1 halves leave in place.
	if c.own.has(r.Iface) {
		if r, err = darwinRouteGet(ctx, host, "default"); err != nil {
			return err
		}
	}
	if strings.HasPrefix(r.Iface, "utun") {
		return fmt.Errorf("netcfg: %s is currently routed through %s (another VPN?); not pinning it there", host, r.Iface)
	}
	err = run(ctx, darwinBypassArgs("add", host, r)...)
	if err != nil && strings.Contains(err.Error(), "File exists") {
		return run(ctx, darwinBypassArgs("change", host, r)...)
	}
	return err
}

// darwinRouteGet asks route(8) how dst ("default" or an address) in host's
// family is reached.
func darwinRouteGet(ctx context.Context, host netip.Addr, dst string) (darwinRoute, error) {
	out, err := exec.CommandContext(ctx, "route", "-n", "get", darwinFamily(host), dst).Output()
	if err != nil {
		return darwinRoute{}, fmt.Errorf("netcfg: route lookup for %s: %w", dst, err)
	}
	return parseDarwinRouteGet(string(out))
}

func (darwinCfg) DelBypass(ctx context.Context, host netip.Addr) error {
	return run(ctx, darwinBypassArgs("delete", host, darwinRoute{})...)
}

var errDarwinEndpoint = errors.New("netcfg: macOS nodes are endpoints only (no forwarding or NAT)")

func (darwinCfg) EnableForwarding(context.Context) error { return errDarwinEndpoint }

func (darwinCfg) AllowForward(context.Context, string, bool) (bool, error) { return false, nil }

func (darwinCfg) SetNAT(_ context.Context, _ netip.Prefix, dsts []netip.Prefix, _ string) error {
	if len(dsts) == 0 {
		return nil
	}
	return errDarwinEndpoint
}

// run executes a command; route(8) reports some failures on stdout with
// exit status 0 ("route: writing to routing socket: File exists"), so the
// output is inspected as well.
func run(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err == nil && args[0] == "route" && (strings.Contains(text, "File exists") || strings.Contains(text, "not in table") || strings.Contains(text, "bad address")) {
		err = errors.New("route failed")
	}
	if err != nil {
		return fmt.Errorf("netcfg: %s: %w: %s", strings.Join(args, " "), err, text)
	}
	return nil
}
