package node

import (
	"net/netip"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

func routeSet(t *testing.T, snap *registry.Snapshot, recv registry.Node) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, r := range advertisedRoutes(snap, recv) {
		out[r.StartIP.String()+"-"+r.EndIP.String()] = true
	}
	return out
}

func has(t *testing.T, snap *registry.Snapshot, recv registry.Node, prefix string) bool {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	want := prefixToRoute(p)
	return routeSet(t, snap, recv)[want.StartIP.String()+"-"+want.EndIP.String()]
}

// A hub does not advertise a network back to the node that announces it: the
// router reaches it on its own, and a route through the hub would send its
// own traffic for that network into the tunnel it came from. An HA pair
// announcing the same network is the case that made this visible.
func TestAHubDoesNotAdvertiseANetworkToItsOwnRouter(t *testing.T) {
	pool := netip.MustParsePrefix("10.25.0.0/16")
	hub := registry.Node{ID: "hub", Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("10.20.0.0/16"), Mode: registry.ModeSNAT}}}
	router := registry.Node{ID: "router", Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("192.168.3.0/24"), Mode: registry.ModeRouted}}}
	router2 := registry.Node{ID: "router2", Prefixes: router.Prefixes} // the same network, HA
	exit := registry.Node{ID: "exit", Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Mode: registry.ModeSNAT}}}
	snap := &registry.Snapshot{Pool: pool, Self: hub, Peers: []registry.Node{router, router2, exit}}

	if has(t, snap, router, "192.168.3.0/24") {
		t.Error("the router is told to reach its own network through the hub")
	}
	if !has(t, snap, router, "10.20.0.0/16") || !has(t, snap, router, "0.0.0.0/0") || !has(t, snap, router, "10.25.0.0/16") {
		t.Errorf("the router lost routes it needs: %v", routeSet(t, snap, router))
	}
	// the other half of the pair learns nothing about that network either
	if has(t, snap, router2, "192.168.3.0/24") {
		t.Error("the second router of the pair is sent to the first")
	}
	// everyone else does learn it
	if !has(t, snap, exit, "192.168.3.0/24") {
		t.Error("the exit node did not learn the routers' network")
	}
}

// A default route of one's own says nothing about which networks a node
// reaches by itself, so an exit node keeps learning the specific ones; and a
// router that announces a narrower network still learns the broader one.
func TestAdvertisedRoutesLeaveOutOnlyEqualOrBroaderNetworks(t *testing.T) {
	pool := netip.MustParsePrefix("10.25.0.0/16")
	hub := registry.Node{ID: "hub", Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("192.168.3.0/24"), Mode: registry.ModeSNAT}}}
	exit := registry.Node{ID: "exit", Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Mode: registry.ModeSNAT}}}
	narrow := registry.Node{ID: "narrow", Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("192.168.3.128/25"), Mode: registry.ModeRouted}}}
	snap := &registry.Snapshot{Pool: pool, Self: hub, Peers: []registry.Node{exit, narrow}}

	if !has(t, snap, exit, "192.168.3.0/24") {
		t.Error("an exit node stopped learning a specific network because it announces 0.0.0.0/0")
	}
	if !has(t, snap, narrow, "192.168.3.0/24") {
		t.Error("a router announcing a /25 did not learn the /24 around it")
	}
	if has(t, snap, hub, "192.168.3.0/24") {
		t.Error("a hub is told to reach its own network through itself")
	}
}
