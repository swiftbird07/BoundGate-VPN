package node

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/profile"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// routeNet records the tunnel routes; everything else is the embedded nil
// Configurator and must not be called.
type routeNet struct {
	netcfg.Configurator
	added, deleted []string
}

func (r *routeNet) AddRoute(_ context.Context, dst netip.Prefix, _ string) error {
	r.added = append(r.added, dst.String())
	return nil
}

func (r *routeNet) DelRoute(_ context.Context, dst netip.Prefix, _ string) error {
	r.deleted = append(r.deleted, dst.String())
	return nil
}

// A subnet router with the full profile takes the default route from an exit
// node, but not for the network it announces itself: splitDefault's halves
// would otherwise cover it, the kernel would send the forwarded packets back
// into the tunnel, and the hub would refuse them as a source that is not
// this tunnel's.
func TestRoutesLeaveOutWhatThisNodeAnnounces(t *testing.T) {
	rec := &routeNet{}
	n := &Node{net: rec, log: slog.New(slog.DiscardHandler), cfg: Config{AllowOverlap: true}}
	self := registry.Node{ID: "router", Prefixes: []registry.Prefix{
		{Prefix: netip.MustParsePrefix("192.168.3.0/24"), Mode: registry.ModeRouted},
	}}
	s := &session{n: n, self: self, pool: netip.MustParsePrefix("10.25.0.0/16"),
		profile: profile.Full(), ifname: "bg0"}
	own := ownNetworks(self)
	s.own.Store(&own)
	m := &spokeManager{s: s, links: map[transport.DeviceID]*hubLink{
		"hub": {tunnel: &transport.ClientTunnel{}, advertised: []netip.Prefix{
			netip.MustParsePrefix("10.25.0.0/16"),
			netip.MustParsePrefix("10.20.0.0/16"),
			netip.MustParsePrefix("192.168.3.0/24"),
			netip.MustParsePrefix("0.0.0.0/0"),
		}},
	}}
	m.installed = map[netip.Prefix]bool{}

	m.mu.Lock()
	m.applyRoutesLocked()
	m.mu.Unlock()

	if slices.Contains(rec.added, "192.168.3.0/24") {
		t.Errorf("the node's own network was routed through the tunnel: %v", rec.added)
	}
	for _, r := range rec.added {
		p := netip.MustParsePrefix(r)
		if p.Contains(netip.MustParseAddr("192.168.3.7")) {
			t.Errorf("%s covers the node's own network: %v", r, rec.added)
		}
	}
	if !slices.Contains(rec.added, "10.20.0.0/16") {
		t.Errorf("the hub's LAN is not routed: %v", rec.added)
	}
	// the default route still arrives, in the pieces that are left of it
	var wan bool
	for _, r := range rec.added {
		if p := netip.MustParsePrefix(r); p.Addr() == netip.MustParseAddr("0.0.0.0") && p.Bits() > 0 {
			wan = true
		}
	}
	if !wan {
		t.Errorf("nothing of the exit node's default route was installed: %v", rec.added)
	}
	// and the status says why that one network is missing
	if m.skipped[netip.MustParsePrefix("192.168.3.0/24")] == "" {
		t.Errorf("not routed says nothing about the node's own network: %v", m.skipped)
	}
}

// An endpoint that announces nothing routes everything the profile allows.
func TestRoutesOfANodeThatAnnouncesNothing(t *testing.T) {
	rec := &routeNet{}
	n := &Node{net: rec, log: slog.New(slog.DiscardHandler), cfg: Config{AllowOverlap: true}}
	s := &session{n: n, self: registry.Node{ID: "laptop"}, pool: netip.MustParsePrefix("10.25.0.0/16"),
		profile: profile.Full(), ifname: "bg0"}
	m := &spokeManager{s: s, installed: map[netip.Prefix]bool{}, links: map[transport.DeviceID]*hubLink{
		"hub": {tunnel: &transport.ClientTunnel{}, advertised: []netip.Prefix{netip.MustParsePrefix("192.168.3.0/24")}},
	}}
	m.mu.Lock()
	m.applyRoutesLocked()
	m.mu.Unlock()
	if !slices.Contains(rec.added, "192.168.3.0/24") {
		t.Errorf("added %v, want the advertised network", rec.added)
	}
	if len(m.skipped) != 0 {
		t.Errorf("skipped %v", m.skipped)
	}
}
