package node

import (
	"net/netip"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

func TestExactlyOneSideDials(t *testing.T) {
	a := registry.Node{ID: "aaa"}
	b := registry.Node{ID: "bbb"}
	pub := registry.Node{ID: "zzz", PublicAddr: "198.51.100.7:443"}
	pub2 := registry.Node{ID: "yyy", PublicAddr: "198.51.100.8:443"}
	for _, c := range []struct{ x, y registry.Node }{{a, b}, {a, pub}, {b, pub}, {pub, pub2}} {
		if dials(c.x, c.y) == dials(c.y, c.x) {
			t.Fatalf("%s and %s: both or neither would dial", c.x.ID, c.y.ID)
		}
	}
	if !dials(a, pub) || dials(pub, a) {
		t.Fatal("the node without an address dials the one that announces one, whatever the ids")
	}
	if !dials(a, b) {
		t.Fatal("without addresses the smaller id dials")
	}
}

func TestForMe(t *testing.T) {
	s := &session{pool: netip.MustParsePrefix("10.21.0.0/16"), self: registry.Node{OverlayIP: netip.MustParseAddr("10.21.0.3"),
		Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("192.168.178.0/24")}, {Prefix: netip.MustParsePrefix("0.0.0.0/0")}}}}
	for addr, want := range map[string]bool{
		"10.21.0.3":      true,  // this node
		"192.168.178.10": true,  // a network it announces
		"93.184.216.34":  true,  // exit node: the internet
		"10.21.0.9":      false, // another spoke: a spoke does not route between peers, not even as exit node
	} {
		if got := s.forMe(netip.MustParseAddr(addr)); got != want {
			t.Errorf("forMe(%s) = %v, want %v", addr, got, want)
		}
	}
}
