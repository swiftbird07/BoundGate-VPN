//go:build linux

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/godbus/dbus/v5"
)

// systemd-resolved is where a Linux host's names are resolved, and it takes
// resolvers per link: the tunnel device gets the hub's resolvers and the
// routing domain "~.", which sends every name there instead of to the
// resolver of the network the machine sits in. That is what a dynamic access
// list needs (the hub only learns a name when it sees the query, docs/ACL.md)
// and what a user expects of a tunnel that routes everything.
//
// Nothing else on the host is touched: /etc/resolv.conf stays as it is, the
// setting lives on the link and dies with it. A machine without resolved
// keeps its resolver and the node says so in its status.
const (
	resolvedService = "org.freedesktop.resolve1"
	resolvedPath    = dbus.ObjectPath("/org/freedesktop/resolve1")
	resolvedManager = "org.freedesktop.resolve1.Manager"
)

// resolvedAddr is resolved's (iay): the address family and the address in
// its wire form, four bytes or sixteen.
type resolvedAddr struct {
	Family  int32
	Address []byte
}

// resolvedDomain is resolved's (sb): a domain and whether it only routes
// queries (true) instead of also being a search domain.
type resolvedDomain struct {
	Domain      string
	RoutingOnly bool
}

// busCall is the one thing this file needs from D-Bus. The tests pass their
// own, so the messages are checked without a bus.
type busCall interface {
	call(ctx context.Context, method string, args ...any) error
	Close() error
}

// ErrNoResolver says the host has no resolver that takes per-link settings.
// The node keeps the system's resolver and reports it; it is not a reason to
// refuse the overlay.
var ErrNoResolver = errors.New("netcfg: no systemd-resolved on the system bus")

// SetLinkDNS implements LinkDNSConfigurator.
func (c linuxCfg) SetLinkDNS(ctx context.Context, ifname string, servers []netip.Addr) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("netcfg: resolver for %s: %w", ifname, err)
	}
	bus, err := dialSystemBus()
	if err != nil {
		return err
	}
	defer bus.Close()
	return setLinkDNS(ctx, bus, int32(iface.Index), servers)
}

// setLinkDNS is the conversation itself, without the bus: either the hub's
// resolvers plus "~." for this link, or the link given back.
func setLinkDNS(ctx context.Context, bus busCall, index int32, servers []netip.Addr) error {
	if len(servers) == 0 {
		// RevertLink drops everything that was set for this link, resolvers
		// and domains together
		if err := bus.call(ctx, resolvedManager+".RevertLink", index); err != nil {
			return fmt.Errorf("netcfg: give the resolver back: %w", err)
		}
		return nil
	}
	addrs := make([]resolvedAddr, 0, len(servers))
	for _, s := range servers {
		switch {
		case s.Is4():
			b := s.As4()
			addrs = append(addrs, resolvedAddr{Family: afINET, Address: b[:]})
		case s.Is4In6():
			b := s.Unmap().As4()
			addrs = append(addrs, resolvedAddr{Family: afINET, Address: b[:]})
		default:
			b := s.As16()
			addrs = append(addrs, resolvedAddr{Family: afINET6, Address: b[:]})
		}
	}
	if err := bus.call(ctx, resolvedManager+".SetLinkDNS", index, addrs); err != nil {
		return fmt.Errorf("netcfg: hand the resolvers to systemd-resolved: %w", err)
	}
	// "~." is a routing domain, not a search domain: every name is asked
	// here, and nothing is appended to a name the user typed
	if err := bus.call(ctx, resolvedManager+".SetLinkDomains", index, []resolvedDomain{{Domain: ".", RoutingOnly: true}}); err != nil {
		return fmt.Errorf("netcfg: send all names through the tunnel: %w", err)
	}
	return nil
}

// AF_INET and AF_INET6 as resolved expects them, inline rather than from
// golang.org/x/sys: two numbers that are the same on every Linux.
const (
	afINET  = 2
	afINET6 = 10
)

type systemBus struct{ conn *dbus.Conn }

func (b systemBus) call(ctx context.Context, method string, args ...any) error {
	obj := b.conn.Object(resolvedService, resolvedPath)
	err := obj.CallWithContext(ctx, method, 0, args...).Err
	// the bus is there but resolved is not: the same answer for the caller
	// as a host without a bus at all
	var de dbus.Error
	if errors.As(err, &de) && (de.Name == "org.freedesktop.DBus.Error.ServiceUnknown" || de.Name == "org.freedesktop.DBus.Error.NameHasNoOwner") {
		return fmt.Errorf("%w: %v", ErrNoResolver, err)
	}
	return err
}

func (b systemBus) Close() error { return b.conn.Close() }

// dialSystemBus opens the system bus. Without one (no D-Bus socket in the
// container, a host without resolved) the caller gets ErrNoResolver, which
// the node reports instead of failing.
func dialSystemBus() (busCall, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoResolver, err)
	}
	return systemBus{conn: conn}, nil
}
