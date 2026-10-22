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

// ArrivalRouter is a configurator that can send replies back the way their
// connection came in (Linux, node option reply_via_arrival). A server that
// hosts services behind a port forward and sends its own traffic through
// the tunnel (profile full over an exit node) otherwise answers the
// forwarded connections through the tunnel, where they die.
type ArrivalRouter interface {
	// ReplyViaArrival turns it on for the tunnel device ifname, before any
	// route through it is added, or off again after the last one is gone.
	ReplyViaArrival(ctx context.Context, ifname string, on bool) error
}

// LinkDNSConfigurator is a configurator that can point the host's resolver at
// the resolvers the hub offers, for the tunnel device alone, and give it back
// (Linux: systemd-resolved over D-Bus).
//
// The apps implement DNSConfigurator instead: there the platform asks for the
// whole network state at once. A daemon has to change something that belongs
// to the host, which is why it is a separate interface and why a node can
// refuse it (option resolver: system).
type LinkDNSConfigurator interface {
	// SetLinkDNS sends every name to servers through ifname. An empty list
	// gives the link back to the system's own configuration.
	SetLinkDNS(ctx context.Context, ifname string, servers []netip.Addr) error
}

// LinkDNS returns the setter when this configurator can really change the
// host's resolver. A Journal takes the call to record it, so asking the
// Journal alone would say yes on every platform; this looks behind it.
func LinkDNS(c Configurator) (LinkDNSConfigurator, bool) {
	l, ok := c.(LinkDNSConfigurator)
	if !ok {
		return nil, false
	}
	if j, ok := c.(*Journal); ok {
		if _, inner := j.Configurator.(LinkDNSConfigurator); !inner {
			return nil, false
		}
	}
	return l, true
}

// DNSSweeper is a configurator that can find resolver entries a node left on
// this host and undo them without a journal to go by. On macOS such an entry
// lives in the system configuration: it outlives the tunnel device, the
// process and even a daemon that was killed between writing it and writing
// its record, and while it is there the machine resolves no name at all
// (R144). `boundgate-node -repair` is the way out that needs no daemon.
type DNSSweeper interface {
	// SweepDNS removes them and returns what it removed.
	SweepDNS(ctx context.Context) ([]string, error)
}

// Sweeper returns the sweeper when this platform has one, looking behind a
// Journal as LinkDNS does.
func Sweeper(c Configurator) (DNSSweeper, bool) {
	if j, ok := c.(*Journal); ok {
		s, ok := j.Configurator.(DNSSweeper)
		return s, ok
	}
	s, ok := c.(DNSSweeper)
	return s, ok
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
