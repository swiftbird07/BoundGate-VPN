package node

import (
	"net/netip"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/flow"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// Three faults in one evening ended in the same signature: allowed,
// forwarded, nothing back - a firewall outside BoundGate, a target without a
// route back to the pool, a routing loop. The flow view says so instead of
// leaving two counters to be compared by eye.
func TestNoReply(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Minute)
	for _, c := range []struct {
		name string
		e    flow.Entry
		want bool
	}{
		{"allowed, nothing came back", flow.Entry{Allowed: true, PacketsIn: 1, Opened: old}, true},
		{"answered", flow.Entry{Allowed: true, PacketsIn: 3, PacketsOut: 2, Opened: old}, false},
		{"denied", flow.Entry{PacketsIn: 1, Opened: old}, false},
		{"just opened: a handshake takes a round trip", flow.Entry{Allowed: true, PacketsIn: 1, Opened: now}, false},
		{"nothing sent either", flow.Entry{Allowed: true, Opened: old}, false},
	} {
		if got := noReply(c.e, now); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// The CLI and the admin UI read it off the flow view.
func TestFlowViewCarriesNoReply(t *testing.T) {
	snap := &registry.Snapshot{Self: registry.Node{ID: "self", Name: "node-a"}}
	e := flow.Entry{ID: "abc", Allowed: true, Decided: true, PacketsIn: 1, BytesIn: 1280,
		Opened:     time.Now().Add(-time.Minute),
		Originator: netip.MustParseAddrPort("10.25.0.8:44000"),
		Target:     netip.MustParseAddrPort("192.168.3.2:8006")}
	v := flowView(snap, e)
	if v.Decision != "allow" || !v.NoReply {
		t.Fatalf("decision %q, no reply %v", v.Decision, v.NoReply)
	}
	e.PacketsOut = 1
	if flowView(snap, e).NoReply {
		t.Fatal("an answered flow is reported as unanswered")
	}
}
