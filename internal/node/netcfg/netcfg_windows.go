//go:build windows

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// winCfg configures Windows through the IP Helper API (winipcfg, the
// package WireGuard for Windows uses): a Wintun adapter, its address and MTU,
// routes on it, and host routes that keep the control plane and hubs on the
// physical path. Windows nodes are endpoints; forwarding and NAT (subnet
// router, hub) are not implemented.
//
// Wintun needs wintun.dll (signed, from wintun.net) next to the executable.
type winCfg struct {
	mu   sync.Mutex
	luid map[string]winipcfg.LUID // adapter name -> LUID
	// bypass remembers where each host route went, to remove exactly it
	bypass map[netip.Addr]routeEntry
}

// New returns the Windows configurator.
func New() Configurator {
	return &winCfg{luid: map[string]winipcfg.LUID{}, bypass: map[netip.Addr]routeEntry{}}
}

// routeMetric: routes through the tunnel win over the physical default
// route; a split 0.0.0.0/1 + 128.0.0.0/1 is longer anyway.
const routeMetric = 0

func (c *winCfg) CreateTUN(name string, mtu int) (tun.Device, string, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, "", fmt.Errorf("netcfg: create Wintun adapter %q (needs administrator rights and wintun.dll next to the program): %w", name, err)
	}
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		dev.Close()
		return nil, "", errors.New("netcfg: unexpected tun device type")
	}
	c.mu.Lock()
	c.luid[name] = winipcfg.LUID(nt.LUID())
	c.mu.Unlock()
	return dev, name, nil
}

func (c *winCfg) adapter(ifname string) (winipcfg.LUID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, ok := c.luid[ifname]
	if !ok {
		return 0, fmt.Errorf("netcfg: no adapter %q", ifname)
	}
	return l, nil
}

func (c *winCfg) SetAddress(_ context.Context, ifname string, addr netip.Prefix, mtu int) error {
	luid, err := c.adapter(ifname)
	if err != nil {
		return err
	}
	if err := luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{addr}); err != nil {
		return fmt.Errorf("netcfg: address %s on %s: %w", addr, ifname, err)
	}
	iface, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return fmt.Errorf("netcfg: %s: %w", ifname, err)
	}
	iface.NLMTU = uint32(mtu)
	// a low interface metric: DNS and routes of equal length prefer the tunnel
	iface.UseAutomaticMetric = false
	iface.Metric = 5
	iface.SitePrefixLength = 0
	if err := iface.Set(); err != nil {
		return fmt.Errorf("netcfg: MTU %d on %s: %w", mtu, ifname, err)
	}
	return nil
}

func (c *winCfg) AddRoute(_ context.Context, dst netip.Prefix, ifname string) error {
	luid, err := c.adapter(ifname)
	if err != nil {
		return err
	}
	err = luid.AddRoute(dst.Masked(), onLink(dst), routeMetric)
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: route %s on %s: %w", dst, ifname, err)
	}
	return nil
}

func (c *winCfg) DelRoute(_ context.Context, dst netip.Prefix, ifname string) error {
	luid, err := c.adapter(ifname)
	if err != nil {
		return err
	}
	err = luid.DeleteRoute(dst.Masked(), onLink(dst))
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil
	}
	return err
}

func onLink(p netip.Prefix) netip.Addr {
	if p.Addr().Is6() {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

func (c *winCfg) tunnelIndexes() map[uint32]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	skip := map[uint32]bool{}
	for _, l := range c.luid {
		if row, err := l.Interface(); err == nil {
			skip[row.InterfaceIndex] = true
		}
	}
	return skip
}

func (c *winCfg) AddBypass(_ context.Context, host netip.Addr) error {
	family := winipcfg.AddressFamily(windows.AF_INET)
	if host.Is6() {
		family = windows.AF_INET6
	}
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return fmt.Errorf("netcfg: routing table: %w", err)
	}
	table := make([]routeEntry, 0, len(rows))
	ifMetric := map[uint32]uint32{}
	for i := range rows {
		r := &rows[i]
		m, seen := ifMetric[r.InterfaceIndex]
		if !seen {
			if ipif, err := r.InterfaceLUID.IPInterface(family); err == nil {
				m = ipif.Metric
			}
			ifMetric[r.InterfaceIndex] = m
		}
		table = append(table, routeEntry{Dst: r.DestinationPrefix.Prefix(), NextHop: r.NextHop.Addr(), IfIndex: r.InterfaceIndex, Metric: r.Metric + m})
	}
	best, ok := bestRoute(table, host, c.tunnelIndexes())
	if !ok {
		return fmt.Errorf("netcfg: no route to %s outside the tunnel", host)
	}
	luid, err := winipcfg.LUIDFromIndex(best.IfIndex)
	if err != nil {
		return err
	}
	dst := netip.PrefixFrom(host, host.BitLen())
	nh := best.NextHop
	if !nh.IsValid() {
		nh = onLink(dst)
	}
	err = luid.AddRoute(dst, nh, 0)
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("netcfg: host route for %s via %s: %w", host, nh, err)
	}
	best.NextHop = nh
	c.mu.Lock()
	c.bypass[host] = best
	c.mu.Unlock()
	return nil
}

// DelBypass removes the host route. After a crash (the cleanup journal
// replays this) the node does not know where it went and removes every host
// route to exactly that address outside the tunnel.
func (c *winCfg) DelBypass(_ context.Context, host netip.Addr) error {
	dst := netip.PrefixFrom(host, host.BitLen())
	c.mu.Lock()
	r, known := c.bypass[host]
	delete(c.bypass, host)
	c.mu.Unlock()
	if known {
		luid, err := winipcfg.LUIDFromIndex(r.IfIndex)
		if err != nil {
			return err
		}
		if err := luid.DeleteRoute(dst, r.NextHop); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return err
		}
		return nil
	}
	family := winipcfg.AddressFamily(windows.AF_INET)
	if host.Is6() {
		family = windows.AF_INET6
	}
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return err
	}
	skip := c.tunnelIndexes()
	for i := range rows {
		if rows[i].DestinationPrefix.Prefix() == dst && !skip[rows[i].InterfaceIndex] {
			_ = rows[i].Delete()
		}
	}
	return nil
}

// ours reports whether a LUID is one of this node's adapters.
func (c *winCfg) ours(l winipcfg.LUID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, o := range c.luid {
		if o == l {
			return true
		}
	}
	return false
}

// Watch gets every route change from the IP Helper API and compares the
// default routes outside the tunnel when one comes (watch.go).
func (c *winCfg) Watch(ctx context.Context, changed func()) bool {
	events := make(chan struct{}, 1)
	cb, err := winipcfg.RegisterRouteChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPforwardRow2) {
		notify(events)
	})
	if err != nil {
		return false
	}
	go func() {
		<-ctx.Done()
		cb.Unregister()
	}()
	go watchDefaults(ctx, events, c.defaults, changed)
	return true
}

// defaults describes the default routes on adapters other than ours.
func (c *winCfg) defaults() (string, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return "", err
	}
	var out []string
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength != 0 || c.ours(r.InterfaceLUID) {
			continue
		}
		out = append(out, fmt.Sprintf("%d %s %d", r.InterfaceIndex, r.NextHop.Addr(), r.Metric))
	}
	return sortedLines(out), nil
}

var errWindowsEndpoint = errors.New("netcfg: Windows nodes are endpoints only (no forwarding or NAT)")

func (c *winCfg) EnableForwarding(context.Context) error { return errWindowsEndpoint }

func (c *winCfg) AllowForward(context.Context, string, bool) (bool, error) { return false, nil }

func (c *winCfg) SetNAT(_ context.Context, _ netip.Prefix, dsts []netip.Prefix, _ string) error {
	if len(dsts) == 0 {
		return nil
	}
	return errWindowsEndpoint
}
