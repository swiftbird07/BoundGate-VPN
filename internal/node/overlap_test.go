package node

import (
	"net/netip"
	"testing"
)

func TestConflictWith(t *testing.T) {
	ln := func(i, p string) localNet { return localNet{Iface: i, Prefix: netip.MustParsePrefix(p)} }
	mac := []localNet{ln("en0", "192.168.178.57/24"), ln("utun8", "10.21.0.9/32"), ln("en7", "10.0.0.5/24")}
	cases := []struct {
		prefix string
		want   string // conflicting interface, "" = none
	}{
		{"10.21.0.0/16", "utun8"},     // overlay pool vs another VPN's tunnel address
		{"192.168.178.0/24", "en0"},   // announced LAN equals the home LAN
		{"192.168.178.128/25", "en0"}, // inside the home LAN
		{"192.168.0.0/16", ""},        // broader than the LAN: on-link stays more specific
		{"10.0.0.0/8", "utun8"},       // would swallow the other VPN's address
		{"10.60.0.0/24", ""},          // unrelated
		{"0.0.0.0/1", ""},             // shadowed default routes never conflict
		{"10.0.0.0/24", "en7"},        // equals a local network
		{"fd00::/8", ""},              // other family
	}
	for _, c := range cases {
		l, ok := conflictWith(netip.MustParsePrefix(c.prefix), mac)
		if got := l.Iface; got != c.want || ok != (c.want != "") {
			t.Errorf("%s: got %q (%v), want %q", c.prefix, got, ok, c.want)
		}
	}
	// a lab spoke: nothing of the lab overlaps its own network
	spoke := []localNet{ln("eth0", "172.30.0.20/24")}
	for _, p := range []string{"10.21.0.0/16", "10.60.0.0/24", "192.168.178.0/24"} {
		if _, ok := conflictWith(netip.MustParsePrefix(p), spoke); ok {
			t.Errorf("lab spoke: %s must not conflict", p)
		}
	}
}
