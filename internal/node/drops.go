package node

import (
	"net/netip"
	"regexp"
	"sync"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// dropWindow summarises refused packets instead of repeating them: the first
// of its kind is reported at once, then one line per window saying how many
// there were since. A node in a routing loop sends hundreds a minute from
// the same address, and one line each buries the log in which the cause has
// to be found — the loop of R138 arrived as 800 identical lines that named
// neither peer nor destination.
type dropWindow struct {
	per time.Duration

	mu   sync.Mutex
	kind map[dropKey]*dropCount
}

type dropKey struct {
	peer transport.DeviceID
	src  netip.Addr
	why  string
}

type dropCount struct {
	since time.Time
	n     uint64
}

func newDropWindow(per time.Duration) *dropWindow {
	return &dropWindow{per: per, kind: make(map[dropKey]*dropCount)}
}

// add counts one refused packet and says whether it should be reported, with
// how many of its kind there were since the last report (1 for the first).
func (d *dropWindow) add(k dropKey) (uint64, bool) {
	if d == nil {
		return 0, false // a session put together without one (tests)
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.kind[k]
	if c == nil {
		if len(d.kind) >= maxDropKinds {
			// a peer sending from thousands of addresses must not grow this
			// map; the kinds already in it keep being counted
			return 0, false
		}
		// reported right away, so this one is already accounted for
		d.kind[k] = &dropCount{since: now}
		return 1, true
	}
	c.n++
	if now.Sub(c.since) < d.per {
		return 0, false
	}
	n := c.n
	c.since, c.n = now, 0
	return n, true
}

// maxDropKinds bounds the map: peer, source address and reason.
const maxDropKinds = 256

// dropsPer is how often one kind of refusal is reported.
const dropsPer = 30 * time.Second

// loopHint explains a source address that belongs to another node of the
// overlay. A peer that sends from a peer's overlay address is almost always
// not an attacker but a node that routes a network of its own through the
// tunnel: the kernel sends the packet it just forwarded back where it came
// from (R138).
func loopHint(snap *registry.Snapshot, from transport.DeviceID, src netip.Addr) string {
	owner, ok := nodeFor(snap, src)
	if !ok || owner.ID == from {
		return ""
	}
	if src == owner.OverlayIP {
		return "the source is " + owner.Name + "'s own overlay address: that node routes one of its own networks through the tunnel (a routing loop) instead of reaching it directly, or this peer sends as someone else"
	}
	return "the source belongs to a network " + owner.Name + " announces, not to this peer"
}

// nodeFor is the node an address belongs to: its overlay address, or the
// most specific network it announces that contains the address.
func nodeFor(snap *registry.Snapshot, addr netip.Addr) (registry.Node, bool) {
	if snap == nil || !addr.IsValid() {
		return registry.Node{}, false
	}
	var best registry.Node
	bits := -1
	for _, n := range append([]registry.Node{snap.Self}, snap.Peers...) {
		if n.OverlayIP == addr {
			return n, true
		}
		for _, p := range n.Prefixes {
			m := p.Prefix.Masked()
			if m.Bits() > bits && m.Bits() > 0 && m.Contains(addr) {
				best, bits = n, m.Bits()
			}
		}
	}
	return best, bits >= 0
}

// libSrcRefused is how connect-ip-go reports a datagram whose source is not
// one of the addresses this node assigned to the peer (conn.go in v0.2.0,
// pinned by R1). On the QUIC path the library refuses such a packet before
// the hub's own check ever sees it, so this line is all there is — and it
// names neither the peer nor the destination.
var libSrcRefused = regexp.MustCompile(`source address not allowed: (\S+?)[\s"]*$`)

// ExplainLibraryLine adds what BoundGate knows to a line a library wrote:
// which node owns the source address a refused datagram carried, and whether
// that looks like a routing loop. It is given to logging.ExplainStdLog.
func (n *Node) ExplainLibraryLine(line string) logging.StdLogNote {
	m := libSrcRefused.FindStringSubmatch(line)
	if m == nil {
		return logging.StdLogNote{}
	}
	src, err := netip.ParseAddr(m[1])
	if err != nil {
		return logging.StdLogNote{}
	}
	note := logging.StdLogNote{Attrs: []any{"src", src, "explained_by", "boundgate"}}
	snap := n.holder.Load()
	owner, ok := nodeFor(snap, src)
	if !ok {
		note.Attrs = append(note.Attrs, "src_node", "none of this network's")
		return note
	}
	note.Attrs = append(note.Attrs, "src_node", owner.Name, "src_node_id", string(owner.ID))
	if src == owner.OverlayIP {
		// Which tunnel it arrived on the library does not say. The owner of
		// the address is the more useful half anyway: that node is the one
		// sending its own traffic back (R138).
		note.Warn = true
		note.Attrs = append(note.Attrs, "meaning",
			"a peer sent a packet from "+owner.Name+"'s overlay address: that node routes one of its own networks through the tunnel (a routing loop) instead of reaching it directly, or a peer sends as someone else")
	}
	return note
}
