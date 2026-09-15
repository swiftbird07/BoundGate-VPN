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
