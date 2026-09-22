package node

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/acl"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/controlclient"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/flow"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// --- ACL glue --------------------------------------------------------------

// admit runs one packet through the flow table; new peer-originated flows
// are decided by the Cedar engine of the current snapshot.
func (s *session) admit(h netparse.Header, pkt []byte, origin flow.Origin) (flow.Outcome, *flow.Entry) {
	out, e := s.flows.Handle(h, pkt, origin, s.decide)
	if out == flow.Pass {
		// Every packet of the overlay passes here, on every node it crosses:
		// TCP connections are told the segment size that fits the tunnel, so
		// they work with a peer whose own MTU is larger (an older client)
		// and with servers that send without the DF bit.
		netparse.ClampMSS(h, pkt, s.mss(h.Version))
	}
	return out, e
}

// mss is the largest TCP segment that fits a tunnel packet of this node.
func (s *session) mss(version int) uint16 {
	if version == 6 {
		return uint16(s.n.cfg.MTU - 60)
	}
	return uint16(s.n.cfg.MTU - 40)
}

// decide is the flow table's Decider. Fail closed: no engine, a stale
// snapshot or an unknown principal denies.
func (s *session) decide(e *flow.Entry) flow.Result {
	eng := s.n.acl.Load()
	if eng == nil || e.Origin.Principal == "" || s.n.holder.Stale(time.Now()) {
		return flow.Result{}
	}
	if r, ok := s.loginPassthrough(e); ok {
		return r
	}
	d := eng.Evaluate(acl.Request{Principal: e.Origin.Principal, Dst: e.Target.Addr(), Port: e.Target.Port(), Proto: e.Proto, SNI: e.SNI, DNSName: e.DNSName})
	return flow.Result{Allow: d.Allow, Policies: d.Policies, Reasons: d.Reasons, Errors: d.Errors, Session: d.Session, Owner: d.Owner, PermitBySNI: d.PermitBySNI}
}

// loginPassthrough decides the flows of an interactive peer that has no user
// session yet, on a hub with login_passthrough: to the listed destinations
// only, whatever the policies say (there is no user they could name). ok is
// false for everyone else, whom the policies decide.
func (s *session) loginPassthrough(e *flow.Entry) (flow.Result, bool) {
	pass := s.n.cfg.LoginPassthrough
	if len(pass) == 0 {
		return flow.Result{}, false
	}
	snap := s.n.holder.Load()
	if snap == nil {
		return flow.Result{}, true
	}
	p, ok := snap.Peer(e.Origin.Principal)
	if !ok || !p.NeedsSession() {
		return flow.Result{}, false
	}
	if _, ok := snap.SessionFor(p.ID, time.Now()); ok {
		return flow.Result{}, false
	}
	for _, pf := range pass {
		if pf.Contains(e.Target.Addr()) {
			return flow.Result{Allow: true, Policies: []string{"login_passthrough"}, Reasons: []string{"before sign-in: " + pf.String()}}, true
		}
	}
	return flow.Result{Reasons: []string{"no user session: only the login passthrough is open"}}, true
}

// flowSweeper expires idle flows.
func (s *session) flowSweeper() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-t.C:
			s.flows.Expire(now)
		}
	}
}

// FlowView is a tracked flow as the CLI shows it.
type FlowView struct {
	ID            string    `json:"id"`
	Proto         string    `json:"proto"`
	Src           string    `json:"src"`
	Dst           string    `json:"dst"`
	Local         bool      `json:"local"`
	Principal     string    `json:"principal,omitempty"`
	PrincipalName string    `json:"principal_name,omitempty"`
	User          string    `json:"user,omitempty"`
	Decision      string    `json:"decision"`
	Policies      []string  `json:"policies,omitempty"`
	SNI           string    `json:"sni,omitempty"`
	DNSName       string    `json:"dns_name,omitempty"`
	BytesIn       uint64    `json:"bytes_in"`
	BytesOut      uint64    `json:"bytes_out"`
	Opened        time.Time `json:"opened"`
	LastSeen      time.Time `json:"last_seen"`
}

func nodeName(snap *registry.Snapshot, id transport.DeviceID) string {
	if snap == nil || id == "" {
		return ""
	}
	if snap.Self.ID == id {
		return snap.Self.Name
	}
	if p, ok := snap.Peer(id); ok {
		return p.Name
	}
	return string(id)
}

func decisionOf(e flow.Entry) string {
	switch {
	case !e.Decided:
		return "local"
	case e.Probing():
		return "pending"
	case e.Allowed:
		return "allow"
	}
	return "deny"
}

func flowView(snap *registry.Snapshot, e flow.Entry) FlowView {
	v := FlowView{ID: e.ID, Proto: acl.ProtoName(e.Proto), Src: e.Originator.String(), Dst: e.Target.String(), Local: e.Origin.Local,
		Principal: string(e.Origin.Principal), PrincipalName: nodeName(snap, e.Origin.Principal), Decision: decisionOf(e),
		Policies: e.Result.Policies, SNI: e.SNI, DNSName: e.DNSName, BytesIn: e.BytesIn, BytesOut: e.BytesOut, Opened: e.Opened, LastSeen: e.LastSeen}
	if e.Result.Session != nil {
		v.User = e.Result.Session.Username
		if v.User == "" {
			v.User = e.Result.Session.Subject
		}
	}
	return v
}

// onFlowEvent writes the flow log record and queues it for the control plane.
func (s *session) onFlowEvent(ev flow.Event) {
	n := s.n
	e := ev.Entry
	snap := n.holder.Load()
	attrs := map[string]any{
		"event":     string(ev.Type),
		"flow":      e.ID,
		"local":     e.Origin.Local,
		"src":       e.Originator.Addr().String(),
		"sport":     e.Originator.Port(),
		"dst":       e.Target.Addr().String(),
		"dport":     e.Target.Port(),
		"proto":     acl.ProtoName(e.Proto),
		"decision":  decisionOf(e),
		"bytes_in":  e.BytesIn,
		"bytes_out": e.BytesOut,
	}
	if e.Origin.Principal != "" {
		attrs["principal"] = string(e.Origin.Principal)
		attrs["principal_name"] = nodeName(snap, e.Origin.Principal)
	}
	if e.SNI != "" {
		attrs["sni"] = e.SNI
	}
	if e.DNSName != "" {
		attrs["dns_name"] = e.DNSName
	}
	if e.Decided {
		attrs["policies"] = orEmptyStrings(e.Result.Policies)
		attrs["reasons"] = orEmptyStrings(e.Result.Reasons)
		if len(e.Result.Errors) > 0 {
			attrs["errors"] = e.Result.Errors
		}
	}
	if se := e.Result.Session; se != nil {
		attrs["session"] = se.ID
		attrs["user"] = se.Subject
		attrs["username"] = se.Username
		attrs["groups"] = se.Groups
	}
	if o := e.Result.Owner; o != nil {
		attrs["owner"] = string(o.ID)
		attrs["owner_name"] = o.Name
	}
	switch ev.Type {
	case flow.EventDeny:
		attrs["reset"] = ev.Reset
		n.denied.Add(1)
	case flow.EventClose:
		attrs["packets_in"] = e.PacketsIn
		attrs["packets_out"] = e.PacketsOut
		attrs["duration_ms"] = ev.At.Sub(e.Opened).Milliseconds()
	}
	if ev.Reason != "" {
		attrs["reason"] = ev.Reason
	}
	args := make([]any, 0, 2*len(attrs))
	for k, v := range attrs {
		args = append(args, k, v)
	}
	n.flowLog.Info("flow "+string(ev.Type), args...)
	n.ship.add(api.ShippedEvent{TS: ev.At, Stream: api.ShipStreamFlow, Message: string(ev.Type), Attrs: attrs})
}

func orEmptyStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// --- tunnel accounting (hub) ----------------------------------------------

// tunnelStats wraps an accepted tunnel to count traffic in both directions
// and to report it to the control plane (connection history).
type tunnelStats struct {
	t       *transport.Tunnel
	peer    registry.Node
	in      atomic.Uint64 // from the peer
	inPkts  atomic.Uint64
	out     atomic.Uint64 // to the peer
	outPkts atomic.Uint64
	via     string // accepted by a spoke: "direct" or "relay <hub>"
	mtu     int    // relayed: larger packets are answered, not sent (paths.go)
}

func newTunnelStats(t *transport.Tunnel, p registry.Node) *tunnelStats {
	return &tunnelStats{t: t, peer: p}
}

// WritePacket implements forward.PacketWriter.
func (ts *tunnelStats) WritePacket(b []byte) ([]byte, error) {
	if ts.mtu > 0 && len(b) > ts.mtu {
		return netparse.FragNeeded(b, ts.mtu), nil
	}
	icmp, err := ts.t.WritePacket(b)
	if err == nil {
		ts.out.Add(uint64(len(b)))
		ts.outPkts.Add(1)
	}
	return icmp, err
}

func (ts *tunnelStats) attrs() map[string]any {
	return map[string]any{
		"tunnel": ts.t.ID(), "peer": string(ts.peer.ID), "peer_name": ts.peer.Name, "peer_addr": ts.t.Peer().SourceIP().String(), "transport": ts.t.Transport(),
		"opened_at": ts.t.Opened().UTC().Format(time.RFC3339Nano),
		"bytes_in":  ts.in.Load(), "bytes_out": ts.out.Load(), "packets_in": ts.inPkts.Load(), "packets_out": ts.outPkts.Load(),
	}
}

func (s *session) trackTunnel(ts *tunnelStats) {
	s.tmu.Lock()
	s.tunnels[ts.t.ID()] = ts
	s.tmu.Unlock()
	s.n.ship.add(api.ShippedEvent{TS: ts.t.Opened(), Stream: api.ShipStreamTunnel, Message: "open", Attrs: ts.attrs()})
}

func (s *session) untrackTunnel(ts *tunnelStats) {
	s.tmu.Lock()
	delete(s.tunnels, ts.t.ID())
	s.tmu.Unlock()
	now := time.Now()
	attrs := ts.attrs()
	attrs["closed_at"] = now.UTC().Format(time.RFC3339Nano)
	// why did it end? our own close code first; a peer that vanished from
	// the snapshot was revoked whoever closed first; else the transport error
	reason := ""
	if code, _, ok := ts.t.LocalClose(); ok {
		reason = codeReason(code)
	}
	if reason == "" {
		if snap := s.n.holder.Load(); snap != nil {
			if _, ok := snap.Peer(ts.peer.ID); !ok {
				reason = "peer revoked"
			}
		}
	}
	if reason == "" {
		reason = tunnelCloseReason(ts.t.Err())
	}
	attrs["reason"] = reason
	attrs["duration_ms"] = now.Sub(ts.t.Opened()).Milliseconds()
	s.n.ship.add(api.ShippedEvent{TS: now, Stream: api.ShipStreamTunnel, Message: "close", Attrs: attrs})
}

// reportTunnels sends the counters of every open tunnel.
func (s *session) reportTunnels() {
	s.tmu.Lock()
	list := make([]*tunnelStats, 0, len(s.tunnels))
	for _, ts := range s.tunnels {
		list = append(list, ts)
	}
	s.tmu.Unlock()
	now := time.Now()
	for _, ts := range list {
		s.n.ship.add(api.ShippedEvent{TS: now, Stream: api.ShipStreamTunnel, Message: "update", Attrs: ts.attrs()})
	}
}

func codeReason(code quic.ApplicationErrorCode) string {
	switch code {
	case transport.ErrCodeRevoked:
		return "peer revoked"
	case transport.ErrCodeSessionExpired:
		return "user session ended"
	case transport.ErrCodeShutdown:
		return "hub shutting down"
	case transport.ErrCodePolicy:
		return "policy"
	case 0:
		return "closed by peer"
	}
	return ""
}

func tunnelCloseReason(err error) string {
	if err == nil {
		return "closed by peer"
	}
	if code, ok := transport.CloseCode(err); ok {
		if r := codeReason(code); r != "" {
			return r
		}
	}
	var idle *quic.IdleTimeoutError
	if errors.As(err, &idle) {
		return "idle timeout"
	}
	msg := err.Error()
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return "connection lost: " + msg
}

// --- log shipping ------------------------------------------------------------

const (
	shipMax   = 10000 // events kept while the control plane is unreachable
	shipBatch = 500   // flush early at this size
	shipEvery = 5 * time.Second
)

// shipper batches flow records and tunnel reports for POST /node/logs.
type shipper struct {
	c   *controlclient.Client
	log *slog.Logger

	mu      sync.Mutex
	buf     []api.ShippedEvent
	dropped uint64
	kick    chan struct{}
	failing bool
}

func newShipper(c *controlclient.Client, log *slog.Logger) *shipper {
	return &shipper{c: c, log: log, kick: make(chan struct{}, 1)}
}

func (s *shipper) add(ev api.ShippedEvent) {
	s.mu.Lock()
	if len(s.buf) >= shipMax {
		s.buf = s.buf[1:]
		s.dropped++
	}
	s.buf = append(s.buf, ev)
	n := len(s.buf)
	s.mu.Unlock()
	if n >= shipBatch {
		select {
		case s.kick <- struct{}{}:
		default:
		}
	}
}

func (s *shipper) run(ctx context.Context) {
	t := time.NewTicker(shipEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kick:
		}
		s.flush(ctx)
	}
}

// flush sends what is buffered, up to the control plane's batch limit per
// request. Failed batches go back to the front of the buffer.
func (s *shipper) flush(ctx context.Context) {
	for {
		s.mu.Lock()
		if len(s.buf) == 0 {
			s.mu.Unlock()
			return
		}
		n := min(len(s.buf), api.ShipMaxEvents)
		batch := make([]api.ShippedEvent, n)
		copy(batch, s.buf[:n])
		s.buf = s.buf[n:]
		dropped := s.dropped
		s.dropped = 0
		s.mu.Unlock()
		if err := s.c.ShipLogs(ctx, batch); err != nil {
			s.mu.Lock()
			s.buf = append(batch, s.buf...)
			if len(s.buf) > shipMax {
				s.dropped += uint64(len(s.buf) - shipMax)
				s.buf = s.buf[len(s.buf)-shipMax:]
			}
			s.dropped += dropped
			first := !s.failing
			s.failing = true
			s.mu.Unlock()
			if first && ctx.Err() == nil {
				s.log.Warn("shipping logs to the control plane failed; buffering", "err", err, "buffered", n)
			}
			return
		}
		s.mu.Lock()
		if s.failing {
			s.log.Info("log shipping recovered")
			s.failing = false
		}
		s.mu.Unlock()
		if dropped > 0 {
			s.log.Warn("log events dropped while the control plane was unreachable", "dropped", dropped)
		}
		if n < api.ShipMaxEvents {
			return
		}
	}
}

// helper for tests and status: number of buffered events.
func (s *shipper) pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buf)
}
