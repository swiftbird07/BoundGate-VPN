package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/quic-go/connect-ip-go"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/flow"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/forward"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// pathManager gives a spoke paths to other nodes that do not end at a hub
// (M7). The tunnel is the one a spoke runs to a hub: QUIC, mTLS against the
// peer's pinned device key, CONNECT-IP. It runs either straight to a peer
// that announces an address, or through a hub's relay, which moves the
// ciphertext and nothing else. The hub path stays what it was and carries
// everything until (and whenever) such a path exists.
//
// Dialing side: the first packet for a peer that has no path asks for one.
// Accepting side: this node is the enforcement point. It admits the peers a
// hub would admit, takes packets only from the addresses the peer's signed
// binding gives it and only for itself and the networks it announces, and
// decides every flow with the ACL.
type pathManager struct {
	s    *session
	cand atomic.Pointer[candidates]
	want chan *candidate

	mu      sync.Mutex
	dialed  map[transport.DeviceID]*path
	servers map[string]*pathServer // "direct", or the id of the relaying hub
}

type candidates struct {
	byIP     map[netip.Addr]*candidate
	prefixes []candPrefix // longest first
}

type candPrefix struct {
	p netip.Prefix
	c *candidate
}

// candidate is a peer a path may be dialed to. next gates attempts: the
// packet path only compares and swaps it.
type candidate struct {
	id    transport.DeviceID
	next  atomic.Int64 // unix nanoseconds; no attempt before
	fails atomic.Int32
}

type pathServer struct {
	srv    *transport.Server
	cancel context.CancelFunc
	via    string
}

// path is a dialed tunnel to a peer.
type path struct {
	peer    registry.Node
	via     string // "direct" or "relay <hub>"
	t       *transport.ClientTunnel
	since   time.Time
	mtu     int // 0: whatever the tunnel takes
	last    atomic.Int64
	in, out atomic.Uint64
}

// PathStatus is the CLI view of a path to a peer that does not end at a hub.
type PathStatus struct {
	Peer     string    `json:"peer"`
	Via      string    `json:"via"`  // direct | relay <hub>
	Side     string    `json:"side"` // dialed | accepted
	Since    time.Time `json:"since"`
	BytesIn  uint64    `json:"bytes_in"`  // from the peer
	BytesOut uint64    `json:"bytes_out"` // to the peer
}

// WritePacket implements forward.PacketWriter.
func (p *path) WritePacket(b []byte) ([]byte, error) {
	if p.mtu > 0 && len(b) > p.mtu {
		// the relayed connection cannot grow its packets; tell the sender
		// the size that fits instead of losing the packet silently
		return netparse.FragNeeded(b, p.mtu), nil
	}
	icmp, err := p.t.WritePacket(b)
	if err == nil {
		p.out.Add(uint64(len(b)))
		p.last.Store(time.Now().UnixNano())
	}
	return icmp, err
}

func newPathManager(s *session) *pathManager {
	pm := &pathManager{s: s, want: make(chan *candidate, 16), dialed: make(map[transport.DeviceID]*path), servers: make(map[string]*pathServer)}
	pm.rebuild(s.n.holder.Load())
	return pm
}

// rebuild recomputes whom a path is dialed to: every approved peer that is
// not a hub (hubs have their link already) and that this node dials rather
// than the other way round (dials), with its overlay address
// and the networks it announces. Default routes are left to the hub path: an
// exit node is chosen by the profile, not by who answers first.
func (pm *pathManager) rebuild(snap *registry.Snapshot) {
	c := &candidates{byIP: make(map[netip.Addr]*candidate)}
	old := pm.cand.Load()
	if snap != nil {
		for _, p := range snap.Peers {
			if p.IsHub() || registry.HasRole(p.Roles, registry.RoleHub) || !dials(snap.Self, p) {
				continue
			}
			cd := &candidate{id: p.ID}
			if old != nil {
				if o := old.byIP[p.OverlayIP]; o != nil && o.id == p.ID {
					cd = o
				}
			}
			c.byIP[p.OverlayIP] = cd
			for _, pf := range p.Prefixes {
				if pf.Prefix.Bits() > 0 {
					c.prefixes = append(c.prefixes, candPrefix{pf.Prefix.Masked(), cd})
				}
			}
		}
	}
	sort.SliceStable(c.prefixes, func(i, j int) bool { return c.prefixes[i].p.Bits() > c.prefixes[j].p.Bits() })
	pm.cand.Store(c)
}

// dials says which of two spokes opens the path, so that the two do not dial
// each other at the same moment: towards the one that announces an address
// if only one does, else the one with the smaller id. The other side's first
// packet to the peer, an answer included, reaches the dialing side over the
// hub and starts the dial there.
func dials(self, peer registry.Node) bool {
	if (self.PublicAddr != "") != (peer.PublicAddr != "") {
		return peer.PublicAddr != ""
	}
	return self.ID < peer.ID
}

// noPath is called by the packet path for a destination no tunnel owns. It
// must be cheap: a map lookup, a short scan, one compare-and-swap.
func (pm *pathManager) noPath(dst netip.Addr) {
	c := pm.cand.Load()
	if c == nil {
		return
	}
	cd := c.byIP[dst]
	if cd == nil {
		for _, e := range c.prefixes {
			if e.p.Contains(dst) {
				cd = e.c
				break
			}
		}
	}
	if cd == nil {
		return
	}
	now := time.Now().UnixNano()
	next := cd.next.Load()
	if now < next || !cd.next.CompareAndSwap(next, now+int64(time.Minute)) {
		return
	}
	select {
	case pm.want <- cd:
	default:
		cd.next.Store(now + int64(time.Second))
	}
}

// run dials what noPath asked for and closes paths nobody uses.
func (pm *pathManager) run(ctx context.Context) {
	idle := time.NewTicker(30 * time.Second)
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case cd := <-pm.want:
			go pm.open(ctx, cd)
		case <-idle.C:
			pm.closeIdle()
		}
	}
}

func (pm *pathManager) open(ctx context.Context, cd *candidate) {
	s := pm.s
	snap := s.n.holder.Load()
	if snap == nil {
		return
	}
	peer, ok := snap.Peer(cd.id)
	if !ok {
		return
	}
	if peer.NeedsSession() {
		// what a hub asks of an interactive node before it admits it holds
		// on a path too, whichever side dialed
		if _, ok := snap.SessionFor(peer.ID, time.Now()); !ok {
			cd.next.Store(time.Now().Add(10 * time.Second).UnixNano())
			return
		}
	}
	pm.mu.Lock()
	_, have := pm.dialed[cd.id]
	pm.mu.Unlock()
	if _, accepted := s.dp.table.Lookup(peer.OverlayIP); have || accepted {
		return // the peer was faster
	}
	p, err := pm.dial(ctx, peer)
	if err != nil {
		// 1, 2, 4 ... 32 minutes: a peer that is down or does not take part
		// costs a hub request now and then, nothing else
		f := min(cd.fails.Add(1), 6)
		cd.next.Store(time.Now().Add(time.Minute << (f - 1)).UnixNano())
		s.n.log.Debug("no path to peer besides the hub", "peer", peer.Name, "err", err)
		return
	}
	cd.fails.Store(0)
	pm.mu.Lock()
	pm.dialed[cd.id] = p
	pm.mu.Unlock()
	s.dp.table.Attach(peer.OverlayIP, p)
	for _, pf := range peer.Prefixes {
		if pf.Prefix.Bits() > 0 {
			s.dp.table.AttachPrefix(pf.Prefix, p)
		}
	}
	s.n.log.Info("path to peer", "peer", peer.Name, "via", p.via)
	s.n.publishStatus()
	go pm.pump(ctx, p)
	<-p.t.Done()
	s.dp.table.Detach(peer.OverlayIP, p)
	for _, pf := range peer.Prefixes {
		if pf.Prefix.Bits() > 0 {
			s.dp.table.DetachPrefix(pf.Prefix, p)
		}
	}
	pm.mu.Lock()
	if pm.dialed[cd.id] == p {
		delete(pm.dialed, cd.id)
	}
	pm.mu.Unlock()
	cd.next.Store(time.Now().Add(5 * time.Second).UnixNano())
	s.n.log.Info("path to peer closed; traffic is back on the hub", "peer", peer.Name, "via", p.via, "reason", tunnelCloseReason(p.t.Err()))
	s.n.publishStatus()
}

// dial tries the peer's own address, then every hub that relays.
func (pm *pathManager) dial(ctx context.Context, peer registry.Node) (*path, error) {
	s := pm.s
	idle, keepAlive := s.n.tunnelTimers()
	cc := transport.ClientConfig{
		TLS:      transport.ClientTLSConfigPinned(s.n.cert, peer.SPKI),
		Template: transport.HubTemplate, IdleTimeout: idle, KeepAlive: keepAlive, HandshakeTimeout: 5 * time.Second,
	}
	var errs []error
	if peer.PublicAddr != "" {
		if addr, err := s.n.hosts.resolveAddrPort(ctx, peer.PublicAddr); err != nil {
			errs = append(errs, err)
		} else if err := s.addBypass(addr.Addr()); err != nil {
			errs = append(errs, err)
		} else {
			cc.GatewayAddr = addr.String()
			if p, err := pm.finish(ctx, cc, peer, "direct", 0); err == nil {
				return p, nil
			} else {
				errs = append(errs, fmt.Errorf("direct %s: %w", addr, err))
			}
		}
	}
	for _, l := range s.spoke.relays() {
		pc, err := l.tunnel.RelayDial(ctx, s.self.OverlayIP, peer.OverlayIP)
		if err != nil {
			errs = append(errs, fmt.Errorf("relay %s: %w", l.hub.Name, err))
			continue
		}
		cc.GatewayAddr, cc.PacketConn, cc.Remote = "", pc, transport.RelayAddr(peer.OverlayIP)
		p, err := pm.finish(ctx, cc, peer, "relay "+l.hub.Name, transport.RelayPathMTU)
		if err == nil {
			// the path lives on that hub connection: when it ends, the path
			// ends now, not after the idle timeout, and the hub path takes over
			go func(carrier *transport.ClientTunnel) {
				select {
				case <-carrier.Done():
					_ = p.t.Close()
				case <-p.t.Done():
				}
			}(l.tunnel)
			return p, nil
		}
		errs = append(errs, fmt.Errorf("relay %s: %w", l.hub.Name, err))
	}
	if len(errs) == 0 {
		return nil, errors.New("the peer announces no address and no connected hub relays")
	}
	return nil, errors.Join(errs...)
}

func (pm *pathManager) finish(ctx context.Context, cc transport.ClientConfig, peer registry.Node, via string, mtu int) (*path, error) {
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	t, err := transport.Dial(dctx, cc)
	if err != nil {
		return nil, err
	}
	// the peer must see us as who the registry says we are
	prefixes, err := t.LocalPrefixes(dctx)
	if err != nil || !slices.Contains(prefixes, netip.PrefixFrom(pm.s.self.OverlayIP, 32)) {
		_ = t.Close()
		return nil, fmt.Errorf("peer assigned %v, registry says %s: %v", prefixes, pm.s.self.OverlayIP, err)
	}
	p := &path{peer: peer, via: via, t: t, since: time.Now(), mtu: mtu}
	p.last.Store(time.Now().UnixNano())
	return p, nil
}

// pump takes what the peer sends on a dialed path.
func (pm *pathManager) pump(ctx context.Context, p *path) {
	buf := make([]byte, forward.Offset+forward.MaxPacket)
	for ctx.Err() == nil {
		n, err := p.t.ReadPacket(buf[forward.Offset:])
		if err != nil {
			return
		}
		p.in.Add(uint64(n))
		p.last.Store(time.Now().UnixNano())
		pm.s.fromPeer(buf[:forward.Offset+n], p.peer, p)
	}
}

// fromPeer is the receiving end of a path, dialed or accepted: the packet
// must come from an address the peer's binding gives it and be for this node
// or a network it announces; then the ACL decides with the peer as principal.
// Nothing is forwarded to another tunnel: a spoke is not a hub.
func (s *session) fromPeer(buf []byte, peer registry.Node, back forward.PacketWriter) {
	pkt := buf[forward.Offset:]
	h, ok := netparse.Parse(pkt)
	if !ok || !allowedSource(peer, h.Src) || !s.forMe(h.Dst) {
		return
	}
	switch out, _ := s.admit(h, pkt, flow.Origin{Principal: peer.ID}); out {
	case flow.Drop:
		return
	case flow.Reset:
		toSender, toReceiver := netparse.TCPReset(pkt)
		if toSender != nil {
			_, _ = back.WritePacket(toSender)
		}
		if toReceiver != nil {
			b := make([]byte, forward.Offset+len(toReceiver))
			copy(b[forward.Offset:], toReceiver)
			_ = s.dp.WriteToTUN(b)
		}
		return
	}
	if err := s.dp.WriteToTUN(buf); err != nil {
		s.n.log.Warn("tun write", "err", err)
	}
}

// forMe: this node's overlay address, or a network it announces, but never
// another overlay address (an exit node announces 0.0.0.0/0, which contains
// the pool; it still does not route between peers).
func (s *session) forMe(dst netip.Addr) bool {
	if dst == s.self.OverlayIP {
		return true
	}
	if s.pool.Contains(dst) {
		return false
	}
	for _, pf := range s.self.Prefixes {
		if pf.Prefix.Contains(dst) {
			return true
		}
	}
	return false
}

func (pm *pathManager) closeIdle() {
	limit := time.Now().Add(-pm.s.n.cfg.PathIdle).UnixNano()
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for _, p := range pm.dialed {
		if p.last.Load() < limit {
			pm.s.n.log.Info("closing unused path", "peer", p.peer.Name, "via", p.via)
			_ = p.t.Close()
		}
	}
}

// networkChanged moves the dialed paths to the new network; relayed ones
// cannot move and end, to be dialed again on demand.
func (pm *pathManager) networkChanged() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for _, p := range pm.dialed {
		pm.s.n.migrate(p.t, "peer "+p.peer.Name)
	}
}

// closePeer ends every path with a peer (revoked, reconfigured).
func (pm *pathManager) closePeer(id transport.DeviceID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if p := pm.dialed[id]; p != nil {
		_ = p.t.Close()
	}
	for _, ps := range pm.servers {
		ps.srv.CloseDevice(id, transport.ErrCodeRevoked, "peer unenrolled or reconfigured")
	}
}

// enforceSessions closes the paths with interactive peers whose user session
// ended, dialed or accepted, as a hub does with its tunnels.
func (pm *pathManager) enforceSessions(snap *registry.Snapshot) {
	if snap == nil {
		return
	}
	now := time.Now()
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for id, p := range pm.dialed {
		if q, ok := snap.Peer(id); ok && q.NeedsSession() {
			if _, ok := snap.SessionFor(id, now); !ok {
				pm.s.n.log.Info("closing path: the peer has no user session", "peer", q.Name)
				_ = p.t.Close()
			}
		}
	}
	for _, ps := range pm.servers {
		for _, id := range ps.srv.ActiveDevices() {
			if p, ok := snap.Peer(id); ok && p.NeedsSession() {
				if _, ok := snap.SessionFor(id, now); !ok {
					ps.srv.CloseDevice(id, transport.ErrCodeSessionExpired, "user session ended")
				}
			}
		}
	}
}

func (pm *pathManager) status() []PathStatus {
	var out []PathStatus
	pm.mu.Lock()
	for _, p := range pm.dialed {
		out = append(out, PathStatus{Peer: p.peer.Name, Via: p.via, Side: "dialed", Since: p.since, BytesIn: p.in.Load(), BytesOut: p.out.Load()})
	}
	pm.mu.Unlock()
	s := pm.s
	s.tmu.Lock()
	for _, ts := range s.tunnels {
		out = append(out, PathStatus{Peer: ts.peer.Name, Via: ts.via, Side: "accepted", Since: ts.t.Opened(), BytesIn: ts.in.Load(), BytesOut: ts.out.Load()})
	}
	s.tmu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Peer+out[i].Side < out[j].Peer+out[j].Side })
	return out
}

// ---- accepting side ----

// listenDirect serves tunnels on a UDP socket of this node (direct.listen).
func (pm *pathManager) listenDirect(ctx context.Context, addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("direct listener: %w", err)
	}
	return pm.serve(ctx, "direct", "direct", pc, false, nil)
}

// hubUp asks a freshly connected hub to relay to this node. Hubs that do
// not relay say so; the node then is reachable through the others, or not
// at all besides the hub path.
func (pm *pathManager) hubUp(ctx context.Context, hub registry.Node, t *transport.ClientTunnel) {
	s := pm.s
	lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	pc, err := t.RelayListen(lctx, s.self.OverlayIP)
	cancel()
	if err != nil {
		var re *transport.RelayError
		if errors.As(err, &re) && re.Status == http.StatusNotImplemented {
			s.n.log.Info("hub does not relay", "hub", hub.Name)
		} else if ctx.Err() == nil {
			s.n.log.Warn("relay listen", "hub", hub.Name, "err", err)
		}
		return
	}
	if err := pm.serve(ctx, string(hub.ID), "relay "+hub.Name, pc, true, t.Done()); err != nil {
		s.n.log.Warn("relay listen", "hub", hub.Name, "err", err)
	}
}

func (pm *pathManager) serve(ctx context.Context, key, via string, pc net.PacketConn, relayed bool, carrier <-chan struct{}) error {
	s := pm.s
	srv, err := transport.NewServer(transport.ServerConfig{
		PacketConn: pc, Relayed: relayed,
		TLS: transport.ServerTLSConfig(s.n.cert, s.n.holder), Lookup: s.n.holder, Template: transport.HubTemplate,
		IdleTimeout: serverIdle, KeepAlive: -1, Logger: s.n.log, StatelessResetKey: s.n.resetKey,
	}, &peerService{s: s, via: via})
	if err != nil {
		_ = pc.Close()
		return err
	}
	if err := srv.Listen(); err != nil {
		_ = pc.Close()
		return err
	}
	sctx, cancel := context.WithCancel(ctx)
	pm.mu.Lock()
	if old := pm.servers[key]; old != nil {
		old.cancel()
	}
	ps := &pathServer{srv: srv, cancel: cancel, via: via}
	pm.servers[key] = ps
	pm.mu.Unlock()
	s.n.log.Info("accepting tunnels from peers", "via", via, "addr", pc.LocalAddr().String())
	go func() {
		if carrier != nil {
			go func() {
				select {
				case <-carrier: // the hub connection this listens on is gone
					cancel()
				case <-sctx.Done():
				}
			}()
		}
		if err := srv.Serve(sctx); err != nil && sctx.Err() == nil {
			s.n.log.Warn("peer listener ended", "via", via, "err", err)
		}
		cancel()
		pm.mu.Lock()
		if pm.servers[key] == ps {
			delete(pm.servers, key)
		}
		pm.mu.Unlock()
	}()
	return nil
}

func (pm *pathManager) stop() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for _, p := range pm.dialed {
		_ = p.t.Close()
	}
	for _, ps := range pm.servers {
		ps.cancel()
	}
}

// peerService is the transport.Handler of a spoke: it admits whom a hub
// would admit, but only to this node.
type peerService struct {
	s   *session
	via string
}

// Accept implements transport.Handler.
func (h *peerService) Accept(_ context.Context, peer transport.AuthenticatedPeer) (transport.TunnelConfig, int, error) {
	n := h.s.n
	snap := n.holder.Load()
	if snap == nil || n.holder.Stale(time.Now()) {
		return transport.TunnelConfig{}, http.StatusServiceUnavailable, nil
	}
	p, ok := snap.Peer(peer.DeviceID())
	if !ok {
		return transport.TunnelConfig{}, http.StatusForbidden, nil
	}
	if p.NeedsSession() {
		if _, ok := snap.SessionFor(p.ID, time.Now()); !ok {
			n.log.Info("peer tunnel refused: no user session", "peer", p.Name)
			return transport.TunnelConfig{}, http.StatusForbidden, nil
		}
	}
	assigned := []netip.Prefix{netip.PrefixFrom(p.OverlayIP, 32)}
	for _, pf := range p.Prefixes {
		assigned = append(assigned, pf.Prefix.Masked())
	}
	routes := []connectip.IPRoute{prefixToRoute(netip.PrefixFrom(snap.Self.OverlayIP, 32))}
	for _, pf := range snap.Self.Prefixes {
		if pf.Prefix.Bits() > 0 {
			routes = append(routes, prefixToRoute(pf.Prefix))
		}
	}
	return transport.TunnelConfig{Assigned: assigned, Routes: routes}, http.StatusOK, nil
}

// Release implements transport.Handler.
func (h *peerService) Release(transport.AuthenticatedPeer, transport.TunnelConfig) {}

// Serve implements transport.Handler.
func (h *peerService) Serve(_ context.Context, t *transport.Tunnel) {
	s := h.s
	p, ok := s.n.holder.Load().Peer(t.Peer().DeviceID())
	if !ok {
		return
	}
	ts := newTunnelStats(t, p)
	ts.via = h.via
	if t.Transport() == "relay" {
		ts.mtu = transport.RelayPathMTU
	}
	// what is for the peer or for the networks behind it takes the path it
	// opened, as on the dialing side: only one of the two ever dials
	s.dp.table.Attach(p.OverlayIP, ts)
	defer s.dp.table.Detach(p.OverlayIP, ts)
	for _, pf := range p.Prefixes {
		if pf.Prefix.Bits() > 0 {
			s.dp.table.AttachPrefix(pf.Prefix, ts)
			defer s.dp.table.DetachPrefix(pf.Prefix, ts)
		}
	}
	s.trackTunnel(ts)
	defer s.untrackTunnel(ts)
	s.n.log.Info("peer attached", "peer", p.Name, "via", h.via)
	s.n.publishStatus()
	defer s.n.publishStatus()
	buf := make([]byte, forward.Offset+forward.MaxPacket)
	for {
		n, err := t.ReadPacket(buf[forward.Offset:])
		if err != nil {
			return
		}
		ts.in.Add(uint64(n))
		ts.inPkts.Add(1)
		s.fromPeer(buf[:forward.Offset+n], p, ts)
	}
}
