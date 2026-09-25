package registry

import (
	"net/netip"
	"strings"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
)

func testSnap() *Snapshot {
	return &Snapshot{
		Version: 1,
		Pool:    netip.MustParsePrefix("10.21.0.0/16"),
		Self:    Node{ID: "hub1", SPKI: devicekey.SPKIHash{1}, OverlayIP: netip.MustParseAddr("10.21.0.1"), Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Mode: ModeSNAT}}},
		Peers: []Node{
			{ID: "node-a", SPKI: devicekey.SPKIHash{2}, OverlayIP: netip.MustParseAddr("10.21.0.2"), Tags: []string{"laptop"}},
		},
	}
}

// The pool is not signed, so a node refuses one that would reach beyond a
// private range, and any announced network that would take nodes' addresses.
func TestValidateGuardsThePool(t *testing.T) {
	if err := testSnap().Validate(); err != nil {
		t.Fatalf("an exit node's default route contains the pool, and that is fine: %v", err)
	}
	for pool, ok := range map[string]bool{
		"10.21.0.0/16": true, "100.64.0.0/20": true, "172.16.0.0/12": true, "192.168.7.0/24": true,
		"0.0.0.0/1": false, "8.0.0.0/8": false, "10.0.0.0/7": false, "100.0.0.0/8": false,
	} {
		if got := PrivatePool(netip.MustParsePrefix(pool)); got != ok {
			t.Fatalf("pool %s: %v, want %v", pool, got, ok)
		}
	}
	s := testSnap()
	s.Peers[0].Prefixes = []Prefix{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Mode: ModeRouted}}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "overlaps the overlay pool") {
		t.Fatalf("a router announcing the pool: %v", err)
	}
}

// A tag is something policies read: its change decides the node's flows
// again without tearing down its tunnels.
func TestDiffOfATagChange(t *testing.T) {
	var h Holder
	h.Store(testSnap())
	next := testSnap()
	next.Version = 2
	next.Peers[0].Tags = []string{"laptop", "quarantine"}
	d := h.Store(next)
	if !d.PoliciesChanged || len(d.RemovedPeers) != 0 {
		t.Fatalf("diff %+v", d)
	}
}
