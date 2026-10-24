package node

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/acl"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/flow"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/forward"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
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
	// dns: the primary hub's resolvers the host now asks, and why it does
	// not when it should (read by Status, like routes and skipped)
	dns    []netip.Addr
	dnsErr string
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
	retry      chan bool // poke: retry now; true: the user session changed
}

// HubStatus is the CLI view of one hub link.
type HubStatus struct {
	Name       string    `json:"name"`
	Addr       string    `json:"addr"`
	State      string    `json:"state"`
	Error      string    `json:"error,omitempty"`
	Since      time.Time `json:"since,omitempty"`
	Transport  string    `json:"transport,omitempty"` // quic or tcp (the fallback)
	Primary    bool      `json:"primary"`
	Advertised []string  `json:"advertised,omitempty"`
	// DNS: resolvers the hub offered with this tunnel.
	DNS []string `json:"dns,omitempty"`
	// What this tunnel carried since Since: IP packets from and to the hub.
	transport.TunnelStats
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
		l := &hubLink{hub: h, cancel: cancel, state: "connecting", retry: make(chan bool, 1)}
		m.links[h.ID] = l
		go m.run(ctx, l)
	}
	m.electLocked()
}

// retryNow makes every link that is waiting after a failure dial again
// immediately. session: the own user session appeared (a sign-in, a new
// snapshot). A hub that refused this device is not asked again on a mere
// network change — nothing about the answer would differ, and a full
// handshake on every change is what drained a phone overnight. A sign-in or
// a new snapshot does poke them: it is what a hub older than this node waits
// for, and what changes a refusal into an answer.
func (m *spokeManager) retryNow(session bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.links {
		if l.tunnel == nil && (session || l.state != "refused" && l.state != "login required") {
			select {
			case l.retry <- session:
			default:
			}
		}
	}
}

// networkChanged moves every hub tunnel to the network the device is on
// now (Node.migrate); one that cannot move ends and is dialed again.
//
// migrate takes the node's lock, and the status (under the node's lock)
// reads the links: the links are collected first and moved outside m.mu.
func (m *spokeManager) networkChanged() {
	type move struct {
		t    *transport.ClientTunnel
		what string
	}
	var moves []move
	m.mu.Lock()
	for _, l := range m.links {
		if l.tunnel != nil {
			moves = append(moves, move{l.tunnel, "hub " + l.hub.Name})
		}
	}
	m.mu.Unlock()
	for _, mv := range moves {
		m.s.n.migrate(mv.t, mv.what)
	}
}

// loginRequired reports whether any hub refused the node for lack of a user
// session. This node's hubs never do — a session is a policy matter, not a
// condition of the tunnel (hub.Accept) — but a hub older than this node
// does, and the state says so until it is updated.
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
			wait := backoff
			var de *transport.DialError
			login := errors.As(err, &de) && de.Status == http.StatusForbidden
			if login {
				// Asking again changes nothing until the control plane says
				// something else, and a new snapshot or a sign-in pokes
				// (retryNow): a full handshake every few seconds all night
				// was what drained a phone overnight.
				state, msg = "refused", "the hub does not accept this device (a hub older than this node also refuses it without a user sign-in: boundgatectl login)"
				if fast > 0 {
					fast--
					wait = 2 * time.Second
				} else {
					wait = loginRetry
					// the session may be in a snapshot a polling node has not fetched yet
					n.control.Refresh()
				}
			}
			m.mu.Lock()
			l.state, l.err, l.tunnel = state, msg, nil
			m.mu.Unlock()
			n.log.Warn("hub connection failed", "hub", l.hub.Name, "addr", l.hub.PublicAddr, "err", err, "retry_in", wait)
			n.publishStatus()
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
				if !login {
					backoff = min(backoff*2, 30*time.Second)
				}
			case session := <-l.retry:
				backoff = time.Second
				if session {
					fast = 3
				}
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
		n.log.Info("hub connected", "hub", l.hub.Name, "addr", l.hub.PublicAddr, "advertised", adv, "transport", t.Transport())
		n.publishStatus()
		if m.s.paths != nil {
			go m.s.paths.hubUp(ctx, l.hub, t)
		}

		go m.pump(ctx, t)
		t = m.wait(ctx, l, t)
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
			case transport.ErrCodeNoAnswer:
				reason = "no answer from the hub: " + t.Err().Error()
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

// wait blocks while the link lives. On the TCP fallback it periodically
// tries QUIC again and, when that works, moves the link over without a gap:
// the new tunnel is attached before the old one is closed. Returns the
// tunnel that ended.
func (m *spokeManager) wait(ctx context.Context, l *hubLink, t *transport.ClientTunnel) *transport.ClientTunnel {
	n := m.s.n
	for {
		var probe <-chan time.Time
		if t.Transport() == "tcp" && n.cfg.Transport == "auto" {
			probe = time.After(n.cfg.QUICRetry)
		}
		select {
		case <-t.Done():
			return t
		case <-ctx.Done():
			_ = t.Close()
			return t
		case <-probe:
			nt, adv, err := m.dialWith(ctx, l.hub, "quic")
			if err != nil {
				n.log.Debug("still on the tcp fallback: QUIC did not work", "hub", l.hub.Name, "err", err)
				continue
			}
			m.mu.Lock()
			old := t
			t = nt
			l.tunnel, l.advertised, l.since = nt, adv, time.Now()
			m.s.dp.table.Detach(l.hub.OverlayIP, old)
			m.s.dp.table.Attach(l.hub.OverlayIP, nt)
			m.primary = nil // re-elect so the uplink points at the new tunnel
			m.electLocked()
			m.applyRoutesLocked()
			m.mu.Unlock()
			go m.pump(ctx, nt)
			_ = old.Close()
			if m.s.paths != nil {
				go m.s.paths.hubUp(ctx, l.hub, nt)
			}
			n.log.Info("hub connection moved back to QUIC", "hub", l.hub.Name, "advertised", adv)
			n.publishStatus()
		}
	}
}

// dial connects to a hub with the configured transport preference: QUIC
// first; when its handshake gets no answer (a network that blocks UDP) the
// same tunnel over TCP. An answer from the hub, even a refusal, is never a
// reason to switch transports.
func (m *spokeManager) dial(ctx context.Context, hub registry.Node) (*transport.ClientTunnel, []netip.Prefix, error) {
	switch m.s.n.cfg.Transport {
	case "tcp":
		return m.dialWith(ctx, hub, "tcp")
	case "quic":
		return m.dialWith(ctx, hub, "quic")
	}
	t, adv, err := m.dialWith(ctx, hub, "quic")
	if err == nil || m.s.n.cfg.NoTCPFallback || ctx.Err() != nil {
		return t, adv, err
	}
	var de *transport.DialError
	if errors.As(err, &de) && de.Status != 0 {
		return nil, nil, err // the hub answered over QUIC
	}
	m.s.n.log.Info("QUIC handshake failed; trying the tunnel over TCP", "hub", hub.Name, "err", err)
	t, adv, terr := m.dialWith(ctx, hub, "tcp")
	if terr != nil {
		return nil, nil, fmt.Errorf("quic: %v; tcp: %w", err, terr)
	}
	return t, adv, nil
}

func (m *spokeManager) dialWith(ctx context.Context, hub registry.Node, transportName string) (*transport.ClientTunnel, []netip.Prefix, error) {
	s := m.s
	target := hub.PublicAddr
	if o, ok := s.n.cfg.HubAddrs[hub.Name]; ok {
		target = o
	} else if o, ok := s.n.cfg.HubAddrs[hub.PublicAddr]; ok {
		target = o
	}
	addr, err := s.n.hosts.resolveAddrPort(ctx, target)
	if err != nil {
		return nil, nil, err
	}
	if err := s.addBypass(addr.Addr()); err != nil {
		return nil, nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	idle, keepAlive := s.n.tunnelTimers()
	cc := transport.ClientConfig{
		GatewayAddr:      addr.String(),
		TLS:              transport.ClientTLSConfigPinned(s.n.cert, hub.SPKI),
		Template:         transport.HubTemplate,
		IdleTimeout:      idle,
		KeepAlive:        keepAlive,
		HandshakeTimeout: 5 * time.Second,
	}
	dial := func(cc transport.ClientConfig) (*transport.ClientTunnel, error) {
		if transportName == "tcp" {
			return transport.DialTCP(dctx, cc)
		}
		return transport.Dial(dctx, cc)
	}
	t, err := dial(cc)
	if err != nil {
		// While the overlay is up the hub's name is answered by a hub's
		// resolver (R140): one that answers it with an address of its own
		// cannot pass as this hub (the pin), but it could keep the node from
		// it. The address this hub was reached at before is tried as well.
		good, ok := s.n.hosts.lastGood(target, addr.Addr())
		if !ok || dctx.Err() != nil {
			return nil, nil, err
		}
		s.n.log.Warn("hub name resolves to another address than it was reached at; trying the one that worked", "hub", hub.Name, "resolved", addr.Addr(), "before", good, "err", err)
		if berr := s.addBypass(good); berr != nil {
			return nil, nil, err
		}
		cc.GatewayAddr = netip.AddrPortFrom(good, addr.Port()).String()
		if t, err = dial(cc); err != nil {
			return nil, nil, err
		}
		addr = netip.AddrPortFrom(good, addr.Port())
	}
	s.n.hosts.confirm(target, addr.Addr())
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
	handle := func(n int) {
		defer s.n.guard.catch("hub tunnel")
		pkt := buf[forward.Offset : forward.Offset+n]
		h, ok := netparse.Parse(pkt)
		if !ok {
			return
		}
		var origin flow.Origin
		if owner, ok := acl.Owner(s.n.holder.Load(), h.Src); ok {
			origin.Principal = owner.ID
		}
		switch out, _ := s.admit(h, pkt, origin); out {
		case flow.Drop:
			return
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
			return
		}
		if err := s.dp.WriteToTUN(buf[:forward.Offset+n]); err != nil {
			s.n.log.Warn("tun write", "err", err)
		}
	}
	for ctx.Err() == nil {
		n, err := t.ReadPacket(buf[forward.Offset:])
		if err != nil {
			return
		}
		handle(n)
	}
}

// relays lists the hub links a relay stream can run on, the primary first.
// Every connected hub can: over QUIC the stream is a request stream of the
// tunnel's connection, over the TCP fallback a second connection to the same
// hub (docs/PATHS.md).
func (m *spokeManager) relays() []*hubLink {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*hubLink
	for _, id := range m.order {
		if l := m.links[id]; l != nil && l.tunnel != nil && l.state == "connected" {
			c := *l // the tunnel as it is now; the link may move on
			if l == m.primary {
				out = append([]*hubLink{&c}, out...)
			} else {
				out = append(out, &c)
			}
		}
	}
	return out
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

// recheckRoutes applies the routes again against the machine's networks as
// they are now (the overlap guard).
func (m *spokeManager) recheckRoutes() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applyRoutesLocked()
}

// watchLocalNets applies the routes again whenever the machine's own
// networks change. Joining a Wi-Fi whose network a peer announces (a home
// LAN behind a subnet router) must take that route out of the tunnel at
// once: routed into the tunnel, the Wi-Fi's router, DHCP and DNS are out of
// reach and the phone refuses to switch to it. Platforms that report
// network changes (NetworkChanged) do not rely on this; it is the net for
// those that do not, or not before the new network works.
func (m *spokeManager) watchLocalNets(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	last := localNetsKey(localNets(m.s.ifname))
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if now := localNetsKey(localNets(m.s.ifname)); now != last {
			last = now
			m.s.n.log.Info("the machine's networks changed: routes checked again", "networks", now)
			m.recheckRoutes()
		}
	}
}

func localNetsKey(ls []localNet) string {
	keys := make([]string, 0, len(ls))
	for _, l := range ls {
		keys = append(keys, l.Iface+"="+l.Prefix.String())
	}
	slices.Sort(keys)
	return strings.Join(keys, ",")
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
	// What this node announces it reaches on its own. Routing it through a
	// hub sends its own traffic for that network back into the tunnel, where
	// the hub refuses it as a source that is not this tunnel's, and nothing
	// behind the node is reachable (R118). The overlap guard below cannot see
	// such a network - it is not on an interface of this machine but behind a
	// static route or the gateway - and a profile's default route covers it in
	// any case, because splitDefault's halves beat the machine's own default.
	own := s.ownNetworks()
	for _, p := range s.profile.Effective(adv) {
		for _, o := range own {
			if p.Contains(o.Addr()) && p.Bits() <= o.Bits() {
				skipped[o] = describeOwn(o)
				if _, known := m.skipped[o]; !known {
					s.n.log.Info("not routing a network this node announces itself", "prefix", o, "advertised", p)
				}
			}
		}
	}
	for _, p := range s.profile.EffectiveExcept(adv, own) {
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
	// The resolvers of the primary hub: every name is asked there, through
	// the tunnel, so that the hub sees the query and a dynamic access list
	// can match what the answer named (docs/ACL.md).
	dns := m.resolversLocked()
	for _, a := range dns {
		want[netip.PrefixFrom(a, a.BitLen())] = true
	}
	// On the way out the resolver goes first, before any route is touched:
	// it is the one change that leaves the machine unable to resolve a name
	// at all when it stays behind, so it must not wait behind commands that
	// can hang (R144).
	if len(dns) == 0 {
		m.applyDNSLocked(dns)
	}
	for p := range m.installed {
		if !want[p] {
			ctx, cancel := opCtx()
			err := s.n.net.DelRoute(ctx, p, s.ifname)
			cancel()
			if err != nil {
				s.n.log.Warn("route del", "prefix", p, "err", err)
			}
			delete(m.installed, p)
		}
	}
	for p := range want {
		if !m.installed[p] {
			ctx, cancel := opCtx()
			err := s.n.net.AddRoute(ctx, p, s.ifname)
			cancel()
			if err != nil {
				s.n.log.Warn("route add", "prefix", p, "err", err)
				continue
			}
			m.installed[p] = true
		}
	}
	// after the routes, not before: a resolver gets a host route of its own
	// here, and a host asked to use an address it cannot reach yet may
	// decide it is unreachable (macOS computes that when the resolver is
	// configured)
	if len(dns) > 0 {
		m.applyDNSLocked(dns)
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

// resolversLocked are the resolvers the primary hub offers, or none when the
// node is to keep the host's own (resolver: system).
func (m *spokeManager) resolversLocked() []netip.Addr {
	if m.s.n.cfg.Resolver == ResolverSystem || m.primary == nil || m.primary.tunnel == nil {
		return nil
	}
	return m.primary.tunnel.DNS()
}

// applyDNSLocked points the host at those resolvers, or gives them back when
// the list is empty. An apps' platform takes them with the rest of the
// network state; a daemon has to change something that belongs to the host,
// and when it cannot, that is reported and nothing else is held up: the
// overlay works, only names are resolved outside it.
func (m *spokeManager) applyDNSLocked(dns []netip.Addr) {
	s := m.s
	m.dns, m.dnsErr = dns, ""
	if d, ok := s.n.net.(netcfg.DNSConfigurator); ok {
		d.SetDNS(dns)
		return
	}
	l, ok := netcfg.LinkDNS(s.n.net)
	if !ok {
		if len(dns) > 0 {
			m.dns, m.dnsErr = nil, "this platform's daemon cannot change the host's resolver yet"
		}
		return
	}
	if len(dns) == 0 {
		if !s.resolver {
			// nothing to point anywhere and nothing to give back: a hub that
			// offers no resolvers must not make every apply ask the bus
			return
		}
		if err := giveBackResolver(s.n.log, l, s.ifname); err != nil {
			// s.resolver stays as it is: the host is still pointed at the
			// tunnel, teardown tries again, and the journal keeps the
			// record for the next start
			m.dnsErr = err.Error()
			return
		}
		s.resolver = false
		return
	}
	ctx, cancel := opCtx()
	err := l.SetLinkDNS(ctx, s.ifname, dns)
	cancel()
	if err != nil {
		m.dns, m.dnsErr = nil, err.Error()
		s.noLinkDNS.Do(func() {
			s.n.log.Warn("the host keeps its own resolver: names are resolved outside the tunnel, so a dynamic access list cannot match them by name (docs/ACL.md)",
				"err", err, "resolvers", dns)
		})
		return
	}
	s.resolver = true
}

// dnsState is where names go while the overlay is up: the hub's resolvers the
// host was pointed at, or the reason it was not.
func (m *spokeManager) dnsState() ([]string, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.dns))
	for _, a := range m.dns {
		out = append(out, a.String())
	}
	return out, m.dnsErr
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
		if l.tunnel != nil {
			hs.Transport = l.tunnel.Transport()
			hs.TunnelStats = l.tunnel.Stats()
			for _, a := range l.tunnel.DNS() {
				hs.DNS = append(hs.DNS, a.String())
			}
		}
		for _, a := range l.advertised {
			hs.Advertised = append(hs.Advertised, a.String())
		}
		out = append(out, hs)
	}
	return out
}
