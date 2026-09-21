// Package netcfg applies the node's network configuration on the host: TUN
// device, address, routes, the bypass routes that keep hubs, control plane
// and identity provider reachable outside the tunnel, and (for subnet
// routers) forwarding and NAT.
package netcfg

import (
	"context"
	"errors"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
)

// ErrUnsupported is returned on platforms without an implementation yet.
var ErrUnsupported = errors.New("netcfg: not supported on this platform")

// Configurator is implemented per OS.
type Configurator interface {
	// CreateTUN creates the device and returns it with its actual name.
	CreateTUN(name string, mtu int) (tun.Device, string, error)
	// SetAddress assigns the overlay address to the device and brings it up.
	SetAddress(ctx context.Context, ifname string, addr netip.Prefix, mtu int) error
	// AddRoute sends dst through the device (idempotent).
	AddRoute(ctx context.Context, dst netip.Prefix, ifname string) error
	// DelRoute removes a route added by AddRoute.
	DelRoute(ctx context.Context, dst netip.Prefix, ifname string) error
	// AddBypass pins a host route for host via the current default path so
	// it stays reachable when the tunnel claims a covering prefix.
	AddBypass(ctx context.Context, host netip.Addr) error
	// DelBypass removes a bypass route.
	DelBypass(ctx context.Context, host netip.Addr) error
	// EnableForwarding turns on IP forwarding (subnet routers, hubs).
	EnableForwarding(ctx context.Context) error
	// AllowForward lets the host's packet filter pass what is forwarded from
	// and to the TUN, where a filter is known to drop it (Docker sets the
	// FORWARD policy to DROP); on = false removes the rules again. It reports
	// whether it found such a filter.
	AllowForward(ctx context.Context, ifname string, on bool) (bool, error)
	// SetNAT masquerades traffic from the overlay pool towards each of dsts
	// when it leaves on an interface other than the TUN. An empty dsts
	// removes the rules.
	SetNAT(ctx context.Context, pool netip.Prefix, dsts []netip.Prefix, ifname string) error
}

// Watcher is a configurator that notices when the machine's own networks
// change (another Wi-Fi, a cable, a VPN of someone else). Host routes to the
// control plane and hubs point to the gateway of the network they were set
// on; after a change they must be set again.
type Watcher interface {
	// Watch calls changed, debounced, until ctx ends; false when it cannot
	// watch on this machine.
	Watch(ctx context.Context, changed func()) bool
}
