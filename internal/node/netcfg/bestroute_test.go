package netcfg

import (
	"net/netip"
	"testing"
)

func TestBestRoute(t *testing.T) {
	p, a := netip.MustParsePrefix, netip.MustParseAddr
	table := []routeEntry{
		{Dst: p("0.0.0.0/0"), NextHop: a("192.168.1.1"), IfIndex: 4, Metric: 35}, // Wi-Fi
		{Dst: p("0.0.0.0/0"), NextHop: a("10.0.0.1"), IfIndex: 7, Metric: 25},    // Ethernet, preferred
		{Dst: p("0.0.0.0/1"), IfIndex: 12, Metric: 5},                            // the tunnel's half-default
		{Dst: p("136.243.0.0/16"), NextHop: a("192.168.1.1"), IfIndex: 4, Metric: 40},
		{Dst: p("192.168.1.0/24"), IfIndex: 4, Metric: 35},
	}
	skip := map[uint32]bool{12: true}
	for _, c := range []struct {
		host   string
		ifIdx  uint32
		via    string
		exists bool
	}{
		{"1.1.1.1", 7, "10.0.0.1", true},            // default route with the lower metric; the tunnel's /1 is skipped
		{"136.243.123.200", 4, "192.168.1.1", true}, // the longer prefix wins over the metric
		{"192.168.1.20", 4, "invalid IP", true},     // on-link
	} {
		r, ok := bestRoute(table, a(c.host), skip)
		if ok != c.exists || r.IfIndex != c.ifIdx || r.NextHop.String() != c.via {
			t.Errorf("%s: %+v %v", c.host, r, ok)
		}
	}
	if _, ok := bestRoute(table[2:3], a("1.1.1.1"), skip); ok {
		t.Error("only the tunnel leads there: no bypass")
	}
}
