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
	// SetNAT masquerades traffic from the overlay pool towards each of dsts
	// when it leaves on an interface other than the TUN. An empty dsts
	// removes the rules.
	SetNAT(ctx context.Context, pool netip.Prefix, dsts []netip.Prefix, ifname string) error
}
