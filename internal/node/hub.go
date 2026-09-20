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
	// An interactive node needs a user session (OIDC login) that the
	// control plane bound to this node id; workloads are admitted on their
	// device identity alone. 403 tells the spoke "login required".
	if p.NeedsSession() {
		if _, ok := snap.SessionFor(p.ID, time.Now()); !ok {
			n.log.Info("tunnel refused: no user session", "peer", p.Name, "node", p.ID)
			return transport.TunnelConfig{}, http.StatusForbidden, nil
		}
	}
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
		Routes:   advertisedRoutes(snap, p.ID),
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
// would itself admit: the dialer approved and, if interactive, with a user
// session; the target the overlay address of another approved node. Which
// flows the target then takes is the target's decision (its ACL); the hub
// cannot see them.
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
	if p.NeedsSession() {
		if _, ok := snap.SessionFor(p.ID, time.Now()); !ok {
			return netip.Addr{}, http.StatusForbidden
		}
	}
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
	var dropped uint64
	for {
		n, err := t.ReadPacket(buf[forward.Offset:])
		if err != nil {
			return
		}
		ts.in.Add(uint64(n))
		ts.inPkts.Add(1)
		pkt := buf[forward.Offset : forward.Offset+n]
		hdr, ok := netparse.Parse(pkt)
		if !ok || !allowedSource(p, hdr.Src) {
			// spoofed or malformed: never forward
			dropped++
			if dropped == 1 || dropped%1000 == 0 {
				s.n.log.Warn("dropping packet with unexpected source", "tunnel", t.ID(), "src", hdr.Src, "peer", p.Name, "dropped", dropped)
			}
			continue
		}
		// the ACL: this peer is the principal of every flow it starts
		switch out, _ := s.admit(hdr, pkt, flow.Origin{Principal: p.ID}); out {
		case flow.Drop:
			continue
		case flow.Reset:
			s.reset(pkt, ts)
			continue
		}
		dp.Route(buf[:forward.Offset+n], ts)
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
// router in routed mode, from the networks it announces.
func allowedSource(p registry.Node, src netip.Addr) bool {
	if src == p.OverlayIP {
		return true
	}
	for _, pf := range p.Prefixes {
		if pf.Prefix.Contains(src) {
			return true
		}
	}
	return false
}

// advertisedRoutes is what a hub tells a peer it can reach: the overlay
// pool, the hub's own prefixes and every other peer's prefixes.
func advertisedRoutes(snap *registry.Snapshot, except transport.DeviceID) []connectip.IPRoute {
	seen := map[netip.Prefix]bool{snap.Pool.Masked(): true}
	prefixes := []netip.Prefix{snap.Pool.Masked()}
	add := func(ps []registry.Prefix) {
		for _, p := range ps {
			m := p.Prefix.Masked()
			if !seen[m] {
				seen[m] = true
				prefixes = append(prefixes, m)
			}
		}
	}
	add(snap.Self.Prefixes)
	for _, n := range snap.Peers {
		if n.ID != except {
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
