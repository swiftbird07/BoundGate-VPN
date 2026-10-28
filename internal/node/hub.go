package node

import (
	"context"
	"net/http"
	"net/netip"
	"sort"
	"time"

	connectip "github.com/quic-go/connect-ip-go"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/flow"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/forward"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// hubService implements transport.Handler for the hub role: it admits
// approved peers, assigns their stable overlay address, advertises what the
// overlay can reach and routes their packets.
type hubService struct {
	s *session
}

// Accept implements transport.Handler.
func (h *hubService) Accept(_ context.Context, peer transport.AuthenticatedPeer) (transport.TunnelConfig, int, error) {
	n := h.s.n
	snap := n.holder.Load()
	if snap == nil || n.holder.Stale(time.Now()) {
		return transport.TunnelConfig{}, http.StatusServiceUnavailable, nil
	}
	p, ok := snap.Peer(peer.DeviceID())
	if !ok {
		return transport.TunnelConfig{}, http.StatusForbidden, nil
	}
	// A user session is not a condition of the tunnel. An approved device
	// holding its key is admitted, and what it may then reach is the
	// policies' answer: they see `principal.has_session`, the user and their
	// groups, so a resource that needs a signed-in person says so, and one
	// that needs only the device does not (docs/OIDC.md, R109). The tunnel
	// itself carries nothing a policy did not permit.
	//
	// Per-flow ACL decisions happen in Serve (flow table + Cedar).
	//
	// CONNECT-IP only lets a peer send from, and receive for, its assigned
	// addresses. A subnet router therefore gets its announced prefixes
	// assigned in addition to its overlay address: traffic for the LAN
	// behind it is "for it", and (in routed mode) LAN sources are "from it".
	assigned := []netip.Prefix{netip.PrefixFrom(p.OverlayIP, 32)}
	for _, pf := range p.Prefixes {
		assigned = append(assigned, pf.Prefix.Masked())
	}
	return transport.TunnelConfig{
		Assigned: assigned,
		Routes:   advertisedRoutes(snap, p),
		DNS:      n.cfg.DNS,
	}, http.StatusOK, nil
}

// RelayListen implements transport.RelayHandler: an approved peer may be
// reached through this hub at its own overlay address, nowhere else.
func (h *hubService) RelayListen(peer transport.AuthenticatedPeer, addr netip.Addr) int {
	n := h.s.n
	if n.cfg.NoRelay {
		return http.StatusNotImplemented
	}
	snap := n.holder.Load()
	if snap == nil || n.holder.Stale(time.Now()) {
		return http.StatusServiceUnavailable
	}
	if p, ok := snap.Peer(peer.DeviceID()); !ok || p.OverlayIP != addr {
		return http.StatusForbidden
	}
	return http.StatusOK
}

// RelayDial implements transport.RelayHandler. The hub pairs only nodes it
// would itself admit: the dialer approved, the target the overlay address
// of another approved node. Which flows the target then takes is the
// target's decision (its ACL); the hub cannot see them.
func (h *hubService) RelayDial(peer transport.AuthenticatedPeer, target netip.Addr) (netip.Addr, int) {
	n := h.s.n
	if n.cfg.NoRelay {
		return netip.Addr{}, http.StatusNotImplemented
	}
	snap := n.holder.Load()
	if snap == nil || n.holder.Stale(time.Now()) {
		return netip.Addr{}, http.StatusServiceUnavailable
	}
	p, ok := snap.Peer(peer.DeviceID())
	if !ok {
		return netip.Addr{}, http.StatusForbidden
	}
	// No session check here either: a relay carries a tunnel whose two ends
	// decide for themselves, and the receiving node's policies see the user
	// behind the peer that reaches it.
	for _, q := range snap.Peers {
		if q.OverlayIP == target && q.ID != p.ID {
			return p.OverlayIP, http.StatusOK
		}
	}
	return netip.Addr{}, http.StatusForbidden
}

// Release implements transport.Handler; addresses are static, nothing to free.
func (h *hubService) Release(transport.AuthenticatedPeer, transport.TunnelConfig) {}

// Serve implements transport.Handler: the per-tunnel packet loop from the
// peer into the overlay.
func (h *hubService) Serve(ctx context.Context, t *transport.Tunnel) {
	s := h.s
	snap := s.n.holder.Load()
	p, ok := snap.Peer(t.Peer().DeviceID())
	if !ok {
		return
	}
	dp := s.dp
	ts := newTunnelStats(t, p)
	dp.table.Attach(p.OverlayIP, ts)
	defer dp.table.Detach(p.OverlayIP, ts)
	for _, pf := range p.Prefixes {
		dp.table.AttachPrefix(pf.Prefix, ts)
		s.addPeerRoute(pf.Prefix)
	}
	defer func() {
		for _, pf := range p.Prefixes {
			if still := dp.table.DetachPrefix(pf.Prefix, ts); !still {
				s.delPeerRoute(pf.Prefix)
			}
		}
	}()
	s.trackTunnel(ts)
	defer s.untrackTunnel(ts)
	s.n.log.Info("peer attached", "peer", p.Name, "node", p.ID, "overlay_ip", p.OverlayIP, "prefixes", len(p.Prefixes))

	buf := make([]byte, forward.Offset+forward.MaxPacket)
	handle := func(n int) {
		defer s.n.guard.catch("spoke tunnel")
		pkt := buf[forward.Offset : forward.Offset+n]
		hdr, ok := netparse.Parse(pkt)
		if !ok {
			if c, say := s.drops.add(dropKey{peer: p.ID, why: "malformed packet"}); say {
				s.n.log.Warn("dropping a packet from a peer", "why", "malformed packet",
					"tunnel", t.ID(), "peer", p.Name, "node", p.ID, "bytes", n, "dropped", c)
			}
			return
		}
		if !allowedSource(p, s.pool, s.networks(), hdr.Src) {
			// this address is not this peer's: never forward it
			if c, say := s.drops.add(dropKey{peer: p.ID, src: hdr.Src, why: "source not this peer's"}); say {
				attrs := []any{"why", "source not this peer's", "tunnel", t.ID(), "peer", p.Name, "node", p.ID,
					"peer_overlay_ip", p.OverlayIP, "src", hdr.Src, "dst", hdr.Dst, "proto", hdr.Proto, "dropped", c}
				if hint := loopHint(s.n.holder.Load(), p.ID, hdr.Src); hint != "" {
					attrs = append(attrs, "meaning", hint)
				}
				s.n.log.Warn("dropping a packet from a peer", attrs...)
			}
			return
		}
		// the ACL: this peer is the principal of every flow it starts
		switch out, _ := s.admit(hdr, pkt, flow.Origin{Principal: p.ID}); out {
		case flow.Drop:
			return
		case flow.Reset:
			s.reset(pkt, ts)
			return
		}
		dp.Route(buf[:forward.Offset+n], ts)
	}
	for {
		n, err := t.ReadPacket(buf[forward.Offset:])
		if err != nil {
			return
		}
		ts.in.Add(uint64(n))
		ts.inPkts.Add(1)
		handle(n)
	}
}

// reset aborts the TCP connection of pkt: one RST back to the sender
// through its tunnel, one onwards to the destination.
func (s *session) reset(pkt []byte, from forward.PacketWriter) {
	toSender, toReceiver := netparse.TCPReset(pkt)
	if toSender != nil {
		_, _ = from.WritePacket(toSender)
	}
	if toReceiver != nil {
		b := make([]byte, forward.Offset+len(toReceiver))
		copy(b[forward.Offset:], toReceiver)
		s.dp.Route(b, from)
	}
}

// allowedSource: a peer may send from its overlay address or, as a subnet
// router in routed mode, from the networks it announces, and from those only
// where no more specific network in the snapshot is someone else's (or this
// node's own). An exit node announces 0.0.0.0/0: without these limits it
// could send as the hub, as any other node, or as a host in a router's LAN,
// and the nodes behind the hub would decide its packets as theirs. An
// address in the overlay pool is only ever its owner's.
//
// announced is every network of the snapshot, longest first (announced).
func allowedSource(p registry.Node, pool netip.Prefix, announced []netip.Prefix, src netip.Addr) bool {
	if src == p.OverlayIP {
		return true
	}
	if pool.Contains(src) {
		return false
	}
	best := -1
	for _, pf := range p.Prefixes {
		if pf.Prefix.Contains(src) && pf.Prefix.Bits() > best {
			best = pf.Prefix.Bits()
		}
	}
	if best < 0 {
		return false
	}
	for _, a := range announced {
		if a.Bits() <= best {
			break
		}
		if a.Contains(src) {
			return false
		}
	}
	return true
}

// announced lists every network the snapshot's nodes announce, this node's
// own included, longest first; default routes are left out (every address
// is in one).
func announced(snap *registry.Snapshot) []netip.Prefix {
	var out []netip.Prefix
	for _, n := range append([]registry.Node{snap.Self}, snap.Peers...) {
		for _, p := range n.Prefixes {
			if p.Prefix.Bits() > 0 {
				out = append(out, p.Prefix.Masked())
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bits() > out[j].Bits() })
	return out
}

// ownNetworks is what one node announces, a default route left out: the
// networks it reaches by itself and must never take from a hub, longest
// first. An exit node's 0.0.0.0/0 says nothing about which networks it
// reaches on its own, so it does not count.
func ownNetworks(self registry.Node) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range self.Prefixes {
		if p.Prefix.Bits() > 0 {
			out = append(out, p.Prefix.Masked())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bits() > out[j].Bits() })
	return out
}

// advertisedRoutes is what a hub tells a peer it can reach: the overlay
// pool, the hub's own prefixes and every other peer's prefixes.
//
// Not what the receiver announces itself, as long as its own prefix is equal
// or broader: it reaches that network on its own, and routing it through the
// hub sends its traffic for it back to itself (R118). A router that announces
// a /25 still learns the /24 another node announces, and a default route
// never counts, or an exit node would stop learning specific networks.
func advertisedRoutes(snap *registry.Snapshot, recv registry.Node) []connectip.IPRoute {
	own := ownNetworks(recv)
	mine := func(p netip.Prefix) bool {
		for _, o := range own {
			if o.Contains(p.Addr()) && o.Bits() <= p.Bits() {
				return true
			}
		}
		return false
	}
	seen := map[netip.Prefix]bool{snap.Pool.Masked(): true}
	prefixes := []netip.Prefix{snap.Pool.Masked()}
	add := func(ps []registry.Prefix) {
		for _, p := range ps {
			m := p.Prefix.Masked()
			if !seen[m] && !mine(m) {
				seen[m] = true
				prefixes = append(prefixes, m)
			}
		}
	}
	add(snap.Self.Prefixes)
	for _, n := range snap.Peers {
		if n.ID != recv.ID {
			add(n.Prefixes)
		}
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })
	routes := make([]connectip.IPRoute, 0, len(prefixes))
	for _, p := range prefixes {
		routes = append(routes, prefixToRoute(p))
	}
	return routes
}

func prefixToRoute(p netip.Prefix) connectip.IPRoute {
	p = p.Masked()
	start := p.Addr()
	var end netip.Addr
	if start.Is4() {
		a := start.As4()
		for i := p.Bits(); i < 32; i++ {
			a[i/8] |= 1 << (7 - uint(i%8))
		}
		end = netip.AddrFrom4(a)
	} else {
		a := start.As16()
		for i := p.Bits(); i < 128; i++ {
			a[i/8] |= 1 << (7 - uint(i%8))
		}
		end = netip.AddrFrom16(a)
	}
	return connectip.IPRoute{StartIP: start, EndIP: end}
}
