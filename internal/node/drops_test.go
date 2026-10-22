package node

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// One line per kind, then one per window with a count: a node in a routing
// loop sends hundreds a minute, and a line each buries the log in which the
// cause has to be found.
func TestDropWindowSummarises(t *testing.T) {
	d := newDropWindow(50 * time.Millisecond)
	k := dropKey{peer: "node-a", src: netip.MustParseAddr("10.25.0.8"), why: "source not this peer's"}
	if n, say := d.add(k); !say || n != 1 {
		t.Fatalf("first: %d %v, want 1 true", n, say)
	}
	for range 99 {
		if _, say := d.add(k); say {
			t.Fatal("reported again inside the window")
		}
	}
	// another kind speaks for itself at once
	if _, say := d.add(dropKey{peer: "node-a", src: k.src, why: "malformed packet"}); !say {
		t.Fatal("a different reason was swallowed")
	}
	time.Sleep(60 * time.Millisecond)
	if n, say := d.add(k); !say || n != 100 {
		t.Fatalf("after the window: %d %v, want 100 true", n, say)
	}
	var nilWindow *dropWindow
	if _, say := nilWindow.add(k); say {
		t.Fatal("a session without a window reported something")
	}
}

func loopSnapshot() *registry.Snapshot {
	hub := registry.Node{ID: "hub", Name: "hub-pvpn", OverlayIP: netip.MustParseAddr("10.25.0.2")}
	router := registry.Node{ID: "router", Name: "orkus_node", OverlayIP: netip.MustParseAddr("10.25.77.10"),
		Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("192.168.3.0/24"), Mode: registry.ModeRouted}}}
	mac := registry.Node{ID: "mac", Name: "martins-macbook", OverlayIP: netip.MustParseAddr("10.25.0.1")}
	return &registry.Snapshot{Pool: netip.MustParsePrefix("10.25.0.0/16"), Self: hub, Peers: []registry.Node{router, mac}}
}

// The source address of a refused packet is the useful half: whoever owns it
// is the node sending its own traffic back.
func TestLoopHint(t *testing.T) {
	snap := loopSnapshot()
	hint := loopHint(snap, "router", netip.MustParseAddr("10.25.0.1"))
	if !strings.Contains(hint, "martins-macbook") || !strings.Contains(hint, "routing loop") {
		t.Errorf("another peer's overlay address: %q", hint)
	}
	if h := loopHint(snap, "mac", netip.MustParseAddr("192.168.3.7")); !strings.Contains(h, "orkus_node") {
		t.Errorf("an address of another node's network: %q", h)
	}
	// the sender's own network is no hint: allowedSource would have let it
	// through, so such a packet is never refused in the first place
	if h := loopHint(snap, "router", netip.MustParseAddr("192.168.3.7")); h != "" {
		t.Errorf("the sender's own network: %q", h)
	}
	if h := loopHint(snap, "mac", netip.MustParseAddr("93.184.216.34")); h != "" {
		t.Errorf("an address of nobody's: %q", h)
	}
}

// connect-ip-go refuses such packets before the hub's own check sees them,
// and its line names neither peer nor destination. The node fills in whose
// address it was.
func TestExplainLibraryLine(t *testing.T) {
	n := &Node{holder: &registry.Holder{}}
	n.holder.Store(loopSnapshot())

	note := n.ExplainLibraryLine("dropping proxied packet: connect-ip: datagram source address not allowed: 10.25.0.1")
	if !note.Warn {
		t.Error("a peer's overlay address as source is not a warning")
	}
	got := attrString(note.Attrs)
	if !strings.Contains(got, "martins-macbook") || !strings.Contains(got, "10.25.0.1") {
		t.Errorf("attrs %v", note.Attrs)
	}

	// an address of a network the sender announces: worth saying, not a loop
	note = n.ExplainLibraryLine("connect-ip: datagram source address not allowed: 192.168.3.7")
	if note.Warn {
		t.Error("an address of someone's own network raised a warning")
	}
	if !strings.Contains(attrString(note.Attrs), "orkus_node") {
		t.Errorf("attrs %v", note.Attrs)
	}

	// anything else is left alone, and nothing panics on nonsense
	for _, line := range []string{"handling stream failed: eof", "", "source address not allowed: not-an-ip",
		"dropping proxied packet (1340 bytes) that can't be proxied: no route"} {
		if note := n.ExplainLibraryLine(line); note.Warn || len(note.Attrs) != 0 {
			t.Errorf("%q: %v", line, note)
		}
	}
}

func attrString(attrs []any) string {
	var b strings.Builder
	for _, a := range attrs {
		b.WriteString(" ")
		switch v := a.(type) {
		case string:
			b.WriteString(v)
		default:
			b.WriteString(netipString(v))
		}
	}
	return b.String()
}

func netipString(v any) string {
	if a, ok := v.(netip.Addr); ok {
		return a.String()
	}
	return ""
}
