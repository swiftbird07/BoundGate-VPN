package node

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/profile"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// hostNet records every change to the host in the order it was made.
type hostNet struct {
	netcfg.Configurator
	ops     []string
	offFail error // the removal of the resolver fails this way
	offs    int   // how often the removal was attempted
}

func (h *hostNet) AddRoute(_ context.Context, dst netip.Prefix, _ string) error {
	h.ops = append(h.ops, "route+ "+dst.String())
	return nil
}

func (h *hostNet) DelRoute(_ context.Context, dst netip.Prefix, _ string) error {
	h.ops = append(h.ops, "route- "+dst.String())
	return nil
}

func (h *hostNet) SetLinkDNS(_ context.Context, ifname string, servers []netip.Addr) error {
	if len(servers) == 0 {
		h.offs++
		if h.offFail != nil {
			h.ops = append(h.ops, "dns- failed")
			return h.offFail
		}
		h.ops = append(h.ops, "dns- "+ifname)
		return nil
	}
	h.ops = append(h.ops, "dns+ "+ifname)
	return nil
}

// hostSession is a spoke with one hub whose tunnel is up, the lab's shape:
// one network behind the hub and a resolver in it.
func hostSession(rec netcfg.Configurator) (*session, *spokeManager) {
	n := &Node{net: rec, log: slog.New(slog.DiscardHandler), cfg: Config{AllowOverlap: true}}
	s := &session{n: n, self: registry.Node{ID: "mac"}, pool: netip.MustParsePrefix("10.21.0.0/16"),
		profile: profile.LANOnly(), ifname: "utun12"}
	own := ownNetworks(s.self)
	s.own.Store(&own)
	m := &spokeManager{s: s, installed: map[netip.Prefix]bool{}, links: map[transport.DeviceID]*hubLink{
		"hub1": {advertised: []netip.Prefix{netip.MustParsePrefix("10.60.0.0/24")}},
	}}
	s.spoke = m
	return s, m
}

// On the way out the resolver has to be given back before any route is
// touched. Measured on 2026-10-22: `route delete` on a device that had just
// gone hung for the whole shared deadline, the resolver's removal came last
// in the queue and was cut off -- and the Mac was left asking an address
// inside a tunnel that no longer existed for every name, which macOS does
// not fall back from. It resolved nothing until the next reboot.
func TestOnTheWayOutTheResolverGoesBeforeTheRoutes(t *testing.T) {
	rec := &hostNet{}
	s, m := hostSession(rec)
	// as the lab left it: the hub's network and the host route of its
	// resolver are installed, the host is pointed at that resolver, and the
	// hub's tunnel has just gone
	s.resolver = true
	m.installed[netip.MustParsePrefix("10.60.0.0/24")] = true
	m.installed[netip.MustParsePrefix("10.60.0.53/32")] = true

	m.mu.Lock()
	m.applyRoutesLocked()
	m.mu.Unlock()
	if len(rec.ops) == 0 || rec.ops[0] != "dns- utun12" {
		t.Fatalf("the resolver must be given back first, got %v", rec.ops)
	}
	if s.resolver {
		t.Error("the session still thinks it owns the host's resolver")
	}
	var routes int
	for _, op := range rec.ops {
		if strings.HasPrefix(op, "route- ") {
			routes++
		}
	}
	if routes == 0 {
		t.Error("the routes were not removed")
	}
}

// A removal that fails is tried again, says so loudly, and is not recorded
// as done: the host really is still pointed at the tunnel, and the status,
// the journal and the next teardown have to agree on that.
func TestAResolverThatCannotBeGivenBackIsTriedAgain(t *testing.T) {
	rec := &hostNet{offFail: errors.New("netcfg: the system configuration did not take the resolver: context deadline exceeded")}
	s, m := hostSession(rec)

	m.mu.Lock()
	m.applyDNSLocked([]netip.Addr{netip.MustParseAddr("10.60.0.53")})
	m.mu.Unlock()
	if !s.resolver {
		t.Fatal("the resolver was not set in the first place")
	}

	m.mu.Lock()
	m.applyDNSLocked(nil)
	m.mu.Unlock()
	if rec.offs != 3 {
		t.Errorf("the removal was attempted %d times, want 3", rec.offs)
	}
	if !s.resolver {
		t.Error("the session recorded the resolver as given back although it is not")
	}
	if _, err := m.dnsState(); err == "" {
		t.Error("the status does not say that the host is still pointed at the tunnel")
	}
}
