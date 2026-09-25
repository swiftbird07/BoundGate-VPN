package forward

import (
	"net/netip"
	"testing"
)

type fake struct{ name string }

func (f *fake) WritePacket([]byte) ([]byte, error) { return nil, nil }

func TestTableLookupOrder(t *testing.T) {
	tb := NewTable()
	a, b, c := &fake{"a"}, &fake{"b"}, &fake{"c"}
	tb.Attach(netip.MustParseAddr("10.21.0.5"), a)
	tb.AttachPrefix(netip.MustParsePrefix("192.168.0.0/16"), b)
	tb.AttachPrefix(netip.MustParsePrefix("192.168.178.0/24"), c)
	tb.AttachPrefix(netip.MustParsePrefix("192.168.178.0/24"), a) // HA second announcer

	if pw, _ := tb.Lookup(netip.MustParseAddr("10.21.0.5")); pw != a {
		t.Fatal("host entry not preferred")
	}
	if pw, _ := tb.Lookup(netip.MustParseAddr("192.168.178.9")); pw != c {
		t.Fatal("longest prefix not chosen")
	}
	if pw, _ := tb.Lookup(netip.MustParseAddr("192.168.1.9")); pw != b {
		t.Fatal("shorter prefix not chosen")
	}
	if _, ok := tb.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("unknown destination matched")
	}
	// c goes away: a still serves the /24
	if still := tb.DetachPrefix(netip.MustParsePrefix("192.168.178.0/24"), c); !still {
		t.Fatal("prefix should still be served by a")
	}
	if pw, _ := tb.Lookup(netip.MustParseAddr("192.168.178.9")); pw != a {
		t.Fatal("failover to second announcer failed")
	}
	if still := tb.DetachPrefix(netip.MustParsePrefix("192.168.178.0/24"), a); still {
		t.Fatal("prefix should be gone")
	}
	if pw, _ := tb.Lookup(netip.MustParseAddr("192.168.178.9")); pw != b {
		t.Fatal("fallback to /16 failed")
	}
	tb.Detach(netip.MustParseAddr("10.21.0.5"), b) // wrong owner: no-op
	if _, ok := tb.Lookup(netip.MustParseAddr("10.21.0.5")); !ok {
		t.Fatal("detach by wrong owner removed entry")
	}
	tb.Detach(netip.MustParseAddr("10.21.0.5"), a)
	if tb.Hosts() != 0 {
		t.Fatal("host not detached")
	}
}

// An exit node announces 0.0.0.0/0. It must not catch the pool (the hub's own
// overlay address, peers the hub does not carry) nor the hub's own networks.
func TestTableReservedAddressesAreNotTakenByAPrefix(t *testing.T) {
	tb := NewTable()
	exit, router, spoke := &fake{"exit"}, &fake{"router"}, &fake{"spoke"}
	tb.SetReserved(netip.MustParsePrefix("10.21.0.0/16"), []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	tb.Attach(netip.MustParseAddr("10.21.0.5"), spoke)
	tb.AttachPrefix(netip.MustParsePrefix("0.0.0.0/0"), exit)
	tb.AttachPrefix(netip.MustParsePrefix("10.20.5.0/24"), router)

	for dst, want := range map[string]*fake{
		"10.21.0.5":  spoke,  // a carried peer: its host entry
		"10.21.0.1":  nil,    // the hub itself: the host stack
		"10.21.0.9":  nil,    // a peer on another hub: not the exit node
		"10.20.1.1":  nil,    // the hub's own LAN
		"10.20.5.7":  router, // a more specific network inside it still routes
		"8.8.8.8":    exit,   // everything else: the exit node
		"192.0.2.10": exit,
	} {
		pw, ok := tb.Lookup(netip.MustParseAddr(dst))
		if want == nil {
			if ok {
				t.Fatalf("%s went to %s", dst, pw.(*fake).name)
			}
			continue
		}
		if !ok || pw != want {
			t.Fatalf("%s: got %v, want %s", dst, pw, want.name)
		}
	}

	// a hub that is an exit node itself keeps its own default route
	tb.SetReserved(netip.MustParsePrefix("10.21.0.0/16"), []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if pw, ok := tb.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatalf("the hub's own exit lost to %s", pw.(*fake).name)
	}
	if pw, _ := tb.Lookup(netip.MustParseAddr("10.20.5.7")); pw != router {
		t.Fatal("a router's network is still more specific than the hub's default")
	}
}
