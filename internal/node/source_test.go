package node

import (
	"net/netip"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// An exit node announces 0.0.0.0/0; it may send from anywhere on the
// internet, but never as another node of the overlay.
func TestAllowedSourceKeepsThePoolToItsOwners(t *testing.T) {
	pool := netip.MustParsePrefix("10.21.0.0/16")
	exit := registry.Node{OverlayIP: netip.MustParseAddr("10.21.0.7"), Prefixes: []registry.Prefix{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Mode: registry.ModeSNAT},
	}}
	for src, want := range map[string]bool{
		"10.21.0.7":     true,  // its own overlay address
		"93.184.216.34": true,  // the internet it carries
		"10.21.0.1":     false, // the hub
		"10.21.0.5":     false, // another node
	} {
		if got := allowedSource(exit, pool, nil, netip.MustParseAddr(src)); got != want {
			t.Fatalf("exit node sending from %s: %v, want %v", src, got, want)
		}
	}
}

// Nor may it send as a host of a network someone else announces more
// specifically: the hub's own LAN, a router's LAN.
func TestAllowedSourceLeavesMoreSpecificNetworksToTheirOwners(t *testing.T) {
	pool := netip.MustParsePrefix("10.21.0.0/16")
	hub := registry.Node{ID: "hub", OverlayIP: netip.MustParseAddr("10.21.0.1"), Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("10.20.0.0/16"), Mode: registry.ModeSNAT}}}
	exit := registry.Node{ID: "exit", OverlayIP: netip.MustParseAddr("10.21.0.7"), Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Mode: registry.ModeSNAT}}}
	router := registry.Node{ID: "router", OverlayIP: netip.MustParseAddr("10.21.0.3"), Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("192.168.178.0/24"), Mode: registry.ModeRouted}}}
	router2 := registry.Node{ID: "router2", OverlayIP: netip.MustParseAddr("10.21.0.4"), Prefixes: router.Prefixes} // HA pair
	snap := &registry.Snapshot{Pool: pool, Self: hub, Peers: []registry.Node{exit, router, router2}}
	nets := announced(snap)
	for _, c := range []struct {
		p     registry.Node
		src   string
		allow bool
	}{
		{exit, "93.184.216.34", true},
		{exit, "10.20.0.1", false},      // the hub's resolver
		{exit, "192.168.178.20", false}, // the router's LAN
		{router, "192.168.178.20", true},
		{router2, "192.168.178.20", true}, // the same network announced twice: both
		{router, "10.20.0.1", false},
	} {
		if got := allowedSource(c.p, pool, nets, netip.MustParseAddr(c.src)); got != c.allow {
			t.Fatalf("%s sending from %s: %v, want %v", c.p.ID, c.src, got, c.allow)
		}
	}
}
