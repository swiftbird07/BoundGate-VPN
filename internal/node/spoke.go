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
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/acl"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/flow"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/forward"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// spokeManager keeps one tunnel to every hub in the snapshot, elects the
// primary (first connected hub in snapshot order) as uplink and keeps the
// kernel routes equal to profile ∩ (union of what connected hubs advertise).
type spokeManager struct {
	s *session

	mu        sync.Mutex
	links     map[transport.DeviceID]*hubLink
	order     []transport.DeviceID
	primary   *hubLink
	installed map[netip.Prefix]bool
	skipped   map[netip.Prefix]string // overlap guard: prefix -> why
}

// hubLink is the state of one hub connection.
type hubLink struct {
	hub        registry.Node
	cancel     context.CancelFunc
	state      string // connecting | connected | error | login required
	err        string
	since      time.Time
	tunnel     *transport.ClientTunnel
	advertised []netip.Prefix
	retry      chan struct{} // poke: retry now
}

// HubStatus is the CLI view of one hub link.
type HubStatus struct {
	Name       string    `json:"name"`
	Addr       string    `json:"addr"`
	State      string    `json:"state"`
	Error      string    `json:"error,omitempty"`
	Since      time.Time `json:"since,omitempty"`
	Primary    bool      `json:"primary"`
	Advertised []string  `json:"advertised,omitempty"`
}

func newSpokeManager(s *session) *spokeManager {
	return &spokeManager{s: s, links: make(map[transport.DeviceID]*hubLink), installed: make(map[netip.Prefix]bool)}
}

// sync starts links for new hubs and stops links to hubs that disappeared
// or changed.
func (m *spokeManager) sync(hubs []registry.Node) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := make(map[transport.DeviceID]registry.Node, len(hubs))
	m.order = m.order[:0]
	for _, h := range hubs {
		want[h.ID] = h
		m.order = append(m.order, h.ID)
	}
	for id, l := range m.links {
		if h, ok := want[id]; !ok || h.SPKI != l.hub.SPKI || h.PublicAddr != l.hub.PublicAddr {
			l.cancel()
			delete(m.links, id)
		}
	}
	for _, h := range hubs {
		if _, ok := m.links[h.ID]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(m.s.ctx)
		l := &hubLink{hub: h, cancel: cancel, state: "connecting", retry: make(chan struct{}, 1)}
		m.links[h.ID] = l
		go m.run(ctx, l)
	}
	m.electLocked()
}

// retryNow makes every link that is waiting after a failure dial again
// immediately (used when the own user session appears).
func (m *spokeManager) retryNow() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.links {
		if l.tunnel == nil {
			select {
			case l.retry <- struct{}{}:
			default:
			}
		}
	}
}

// loginRequired reports whether any hub refused the node for lack of a
// user session.
func (m *spokeManager) loginRequired() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.links {
		if l.state == "login required" {
			return true
		}
	}
	return false
}

// stop closes every link.
func (m *spokeManager) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, l := range m.links {
		l.cancel()
		if l.tunnel != nil {
			_ = l.tunnel.Close()
		}
		delete(m.links, id)
	}
	m.primary = nil
	m.s.dp.setUplink(nil)
}

// run dials a hub until ctx ends, reconnecting with backoff.
func (m *spokeManager) run(ctx context.Context, l *hubLink) {
	n := m.s.n
	backoff := time.Second
	fast := 0 // quick retries left after a poke (the hub may see the session a moment after we do)
	for ctx.Err() == nil {
		t, adv, err := m.dial(ctx, l.hub)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			state, msg := "error", err.Error()
			var de *transport.DialError
			if errors.As(err, &de) && de.Status == http.StatusForbidden {
				state, msg = "login required", "hub refused the tunnel: user login required (boundgatectl login)"
				if fast > 0 {
					fast--
					backoff = 2 * time.Second
				} else {
					backoff = max(backoff, 10*time.Second)
				}
			}
			m.mu.Lock()
			l.state, l.err, l.tunnel = state, msg, nil
			m.mu.Unlock()
			n.log.Warn("hub connection failed", "hub", l.hub.Name, "addr", l.hub.PublicAddr, "err", err, "retry_in", backoff)
			n.publishStatus()
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff = min(backoff*2, 30*time.Second)
			case <-l.retry:
				backoff, fast = time.Second, 3
			}
			continue
		}
		backoff = time.Second
		m.mu.Lock()
		l.state, l.err, l.tunnel, l.advertised, l.since = "connected", "", t, adv, time.Now()
		// The hub itself is reached through its own link, whichever hub
		// is primary: hubs do not forward for each other (M1.5).
		m.s.dp.table.Attach(l.hub.OverlayIP, t)
		m.electLocked()
		m.applyRoutesLocked()
		m.mu.Unlock()
		n.log.Info("hub connected", "hub", l.hub.Name, "addr", l.hub.PublicAddr, "advertised", adv)
		n.publishStatus()

		go m.pump(ctx, t)
		select {
		case <-t.Done():
		case <-ctx.Done():
			_ = t.Close()
		}
		reason := "connection lost"
		revoked := false
		if code, ok := transport.CloseCode(t.Err()); ok {
			switch code {
			case transport.ErrCodeRevoked:
				reason, revoked = "node revoked by hub", true
			case transport.ErrCodeSessionExpired:
				reason = "user session expired"
			case transport.ErrCodeShutdown:
				reason = "hub shutting down"
			case transport.ErrCodePolicy:
				reason = "hub policy: " + t.Err().Error()
			default:
				reason = fmt.Sprintf("hub closed the tunnel (code %d)", code)
			}
		} else if err := t.Err(); err != nil && ctx.Err() == nil {
			reason = "connection lost: " + err.Error()
		}
		m.mu.Lock()
		m.s.dp.table.Detach(l.hub.OverlayIP, t)
		l.state, l.err, l.tunnel, l.advertised = "connecting", reason, nil, nil
		m.electLocked()
		m.applyRoutesLocked()
		m.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		n.log.Warn("hub disconnected", "hub", l.hub.Name, "reason", reason)
		if code, ok := transport.CloseCode(t.Err()); ok && code == transport.ErrCodeSessionExpired {
			m.mu.Lock()
			l.state = "login required"
			m.mu.Unlock()
		}
		n.publishStatus()
		if revoked {
			// The hub knows better than our (possibly stale) snapshot; the
			// control loop confirms via the next snapshot fetch.
			go m.s.close("node revoked by hub " + l.hub.Name)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (m *spokeManager) dial(ctx context.Context, hub registry.Node) (*transport.ClientTunnel, []netip.Prefix, error) {
	s := m.s
	target := hub.PublicAddr
	if o, ok := s.n.cfg.HubAddrs[hub.Name]; ok {
		target = o
	} else if o, ok := s.n.cfg.HubAddrs[hub.PublicAddr]; ok {
		target = o
	}
	addr, err := resolveAddrPort(ctx, target)
	if err != nil {
		return nil, nil, err
	}
	if err := s.addBypass(addr.Addr()); err != nil {
		return nil, nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	t, err := transport.Dial(dctx, transport.ClientConfig{
		GatewayAddr: addr.String(),
		TLS:         transport.ClientTLSConfigPinned(s.n.cert, hub.SPKI),
		Template:    transport.HubTemplate,
		IdleTimeout: 30 * time.Second,
		KeepAlive:   10 * time.Second,
	})
	if err != nil {
		return nil, nil, err
	}
	prefixes, err := t.LocalPrefixes(dctx)
	if err != nil || len(prefixes) == 0 {
		_ = t.Close()
		return nil, nil, fmt.Errorf("hub assigned no address: %v", err)
	}
	if !slices.Contains(prefixes, netip.PrefixFrom(s.self.OverlayIP, 32)) {
		_ = t.Close()
		return nil, nil, fmt.Errorf("hub assigned %v, registry says %s", prefixes, s.self.OverlayIP)
	}
	routes, err := t.Routes(dctx)
	if err != nil {
		_ = t.Close()
		return nil, nil, fmt.Errorf("routes: %w", err)
	}
	var adv []netip.Prefix
	for _, r := range routes {
		adv = append(adv, r.Prefixes()...)
	}
	return t, adv, nil
}

// pump moves packets from a hub tunnel to the host stack. Every connected
// hub may deliver return traffic, not only the primary. Packets that start
// a flow are decided by the ACL with the owner of the source address as
// principal: the hub already checked that the source belongs to that peer.
func (m *spokeManager) pump(ctx context.Context, t *transport.ClientTunnel) {
	s := m.s
	buf := make([]byte, forward.Offset+forward.MaxPacket)
	for ctx.Err() == nil {
		n, err := t.ReadPacket(buf[forward.Offset:])
		if err != nil {
			return
		}
		pkt := buf[forward.Offset : forward.Offset+n]
		h, ok := netparse.Parse(pkt)
		if !ok {
			continue
		}
		var origin flow.Origin
		if owner, ok := acl.Owner(s.n.holder.Load(), h.Src); ok {
			origin.Principal = owner.ID
		}
		switch out, _ := s.admit(h, pkt, origin); out {
		case flow.Drop:
			continue
		case flow.Reset:
			toSender, toReceiver := netparse.TCPReset(pkt)
			if toSender != nil {
				_, _ = t.WritePacket(toSender)
			}
			if toReceiver != nil {
				b := make([]byte, forward.Offset+len(toReceiver))
				copy(b[forward.Offset:], toReceiver)
				_ = s.dp.WriteToTUN(b)
			}
			continue
		}
		if err := s.dp.WriteToTUN(buf[:forward.Offset+n]); err != nil {
			s.n.log.Warn("tun write", "err", err)
		}
	}
}

// electLocked picks the first connected hub in snapshot order as uplink.
func (m *spokeManager) electLocked() {
	var best *hubLink
	for _, id := range m.order {
		if l := m.links[id]; l != nil && l.tunnel != nil {
			best = l
			break
		}
	}
	if best == m.primary {
		return
	}
	m.primary = best
	if best == nil {
		m.s.dp.setUplink(nil)
		m.s.n.log.Warn("no hub connected; overlay traffic is dropped")
		return
	}
	m.s.dp.setUplink(best.tunnel)
	m.s.n.log.Info("primary hub", "hub", best.hub.Name)
}

// applyRoutesLocked makes the kernel routes equal to the effective set.
func (m *spokeManager) applyRoutesLocked() {
	s := m.s
	var adv []netip.Prefix
	for _, l := range m.links {
		if l.tunnel != nil {
			adv = append(adv, l.advertised...)
		}
	}
	want := make(map[netip.Prefix]bool)
	skipped := make(map[netip.Prefix]string)
	var locals []localNet
	if !s.n.cfg.AllowOverlap {
		locals = localNets(s.ifname)
	}
	for _, p := range s.profile.Effective(adv) {
		if p == s.pool.Masked() {
			continue // installed for the session's lifetime
		}
		if l, bad := conflictWith(p, locals); bad {
			skipped[p] = describeConflict(p, l)
			if _, known := m.skipped[p]; !known {
				s.n.log.Warn("not routing an advertised network: this machine already lives in it", "prefix", p, "local", l.Prefix, "iface", l.Iface)
			}
			continue
		}
		for _, q := range splitDefault(p) {
			want[q] = true
		}
	}
	m.skipped = skipped
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for p := range m.installed {
		if !want[p] {
			if err := s.n.net.DelRoute(ctx, p, s.ifname); err != nil {
				s.n.log.Warn("route del", "prefix", p, "err", err)
			}
			delete(m.installed, p)
		}
	}
	for p := range want {
		if !m.installed[p] {
			if err := s.n.net.AddRoute(ctx, p, s.ifname); err != nil {
				s.n.log.Warn("route add", "prefix", p, "err", err)
				continue
			}
			m.installed[p] = true
		}
	}
}

// splitDefault turns 0.0.0.0/0 into two /1 routes so the host's real
// default route is shadowed, never replaced, and comes back untouched.
func splitDefault(p netip.Prefix) []netip.Prefix {
	if p.Bits() == 0 && p.Addr().Is4() {
		return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	}
	return []netip.Prefix{p}
}

// skippedRoutes lists what the overlap guard refused, sorted.
func (m *spokeManager) skippedRoutes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.skipped))
	for _, why := range m.skipped {
		out = append(out, why)
	}
	sort.Strings(out)
	return out
}

// routes returns the installed routes, sorted.
func (m *spokeManager) routes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.installed))
	for p := range m.installed {
		out = append(out, p.String())
	}
	sort.Strings(out)
	return out
}

// hubs returns the link states in snapshot order.
func (m *spokeManager) hubs() []HubStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HubStatus, 0, len(m.order))
	for _, id := range m.order {
		l := m.links[id]
		if l == nil {
			continue
		}
		hs := HubStatus{Name: l.hub.Name, Addr: l.hub.PublicAddr, State: l.state, Error: l.err, Since: l.since, Primary: l == m.primary}
		for _, a := range l.advertised {
			hs.Advertised = append(hs.Advertised, a.String())
		}
		out = append(out, hs)
	}
	return out
}

func resolveAddrPort(ctx context.Context, hostport string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return ap, nil
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("address %q: %w", hostport, err)
	}
	ip, err := resolveHost(ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	p, err := net.LookupPort("udp", port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, uint16(p)), nil
}

func resolveHost(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve %s: %v", host, errors.Join(err))
	}
	return addrs[0].Unmap(), nil
}
