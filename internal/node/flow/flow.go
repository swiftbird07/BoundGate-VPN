// Package flow is the per-node connection table below the ACL: it groups
// packets into flows (5-tuples), asks the policy layer once per new flow
// that arrives from a peer, remembers the verdict, inspects the first
// payload for a TLS server name or DNS question (which may turn a permit
// into a deny), counts bytes and emits open/deny/close events for the flow
// log. Flows the node originates itself are tracked (so return traffic is
// matched) but not decided here; the receiving node decides.
package flow

import (
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"sort"
	"sync"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// Key identifies a flow regardless of direction.
type Key struct {
	A, B  netip.AddrPort // A < B
	Proto uint8
}

// KeyOf normalizes a header into a key. ICMP flows are keyed on the
// addresses only.
func KeyOf(h netparse.Header) Key {
	a := netip.AddrPortFrom(h.Src, h.SrcPort)
	b := netip.AddrPortFrom(h.Dst, h.DstPort)
	if b.Addr().Less(a.Addr()) || a.Addr() == b.Addr() && b.Port() < a.Port() {
		a, b = b, a
	}
	return Key{A: a, B: b, Proto: h.Proto}
}

// Origin says where a packet entered the node.
type Origin struct {
	// Principal is the node the packet comes from (a tunnel peer on a hub,
	// the owner of the source address on a router). Empty with Local.
	Principal transport.DeviceID
	// Local marks packets from the node's own host stack (TUN): the flow is
	// tracked, not decided.
	Local bool
}

// Result is the policy layer's answer for a flow.
type Result struct {
	Allow    bool
	Policies []string
	Reasons  []string
	Errors   []string
	Session  *registry.Session
	Owner    *registry.Node
	// PermitBySNI: denied so far, but a permit may match once the TLS
	// server name is known (acl.Decision.PermitBySNI).
	PermitBySNI bool
	// Names are the names this peer resolved to the destination and that
	// the decision could use (dnsmap); for the flow log.
	Names []string
}

// Decider is asked once per new peer-originated flow, and again when an
// inspected attribute (SNI, DNS name) appears.
type Decider func(e *Entry) Result

// Learner is told about every DNS answer that passes an allowed flow: the
// name of its question, the addresses it names and the smallest time to
// live of those records. The node decides what to keep (dnsmap); the flow
// table only reads what goes by.
type Learner func(e *Entry, name string, addrs []netip.Addr, ttl time.Duration)

// Entry is one tracked flow.
type Entry struct {
	ID         string
	Key        Key
	Originator netip.AddrPort // source of the first packet
	Target     netip.AddrPort
	Proto      uint8
	Origin     Origin

	Decided bool // false for local flows
	Allowed bool
	Result  Result
	SNI     string
	DNSName string

	Opened, LastSeen                         time.Time
	BytesIn, BytesOut, PacketsIn, PacketsOut uint64 // In = from the originator

	sniBuf   []byte
	sniDone  bool
	dnsDone  bool
	closing  bool
	denyOnly bool // cached deny, expires quickly
	// dns: a UDP flow a peer opened to port 53. It is decided message by
	// message (dnsPacket): each query under its own question, each response
	// only as the answer to a query that passed.
	dns        bool
	dnsStarted bool       // the first message was decided
	nameless   bool       // the destination is permitted without a question
	queries    []dnsQuery // queries that passed and wait for their answer
	lastDenied string     // one deny event per refused name, not per retry
	// probing: a TCP flow denied at the SYN that a permit could still allow
	// by server name. The handshake passes, the first payload from the
	// originator is held back until it was read: a ClientHello with a name
	// the policies permit opens the flow, anything else aborts it with
	// RSTs. The server sees a handshake, never a byte of payload.
	probing bool
}

type dnsQuery struct {
	id   uint16
	name string
}

// maxQueries bounds the questions one DNS flow may have in flight; the
// oldest is forgotten (its answer then no longer passes).
const maxQueries = 32

// Probing reports a flow waiting for its TLS server name to be decided.
func (e *Entry) Probing() bool { return e.probing }

// EventType of a flow event.
type EventType string

const (
	EventOpen  EventType = "open"
	EventDeny  EventType = "deny"
	EventClose EventType = "close"
)

// Event is what the flow log receives.
type Event struct {
	Type   EventType
	Entry  Entry // a copy
	Reset  bool  // the deny was enforced with TCP RSTs
	Reason string
	At     time.Time
}

// Outcome of Handle.
type Outcome int

const (
	Drop Outcome = iota
	Pass
	// Reset: drop and answer with TCP RSTs (the decision changed after the
	// handshake, e.g. a forbidden SNI).
	Reset
)

// Timeouts of the table. Embryonic is a TCP flow the other side never
// answered: a SYN to nowhere holds its entry for a minute, not half an hour.
type Timeouts struct {
	TCP, UDP, ICMP, Other, Closing, Deny, Embryonic time.Duration
}

// DefaultTimeouts are used when a field is zero.
var DefaultTimeouts = Timeouts{TCP: 30 * time.Minute, UDP: 2 * time.Minute, ICMP: 30 * time.Second, Other: 2 * time.Minute, Closing: 5 * time.Second, Deny: 10 * time.Second, Embryonic: time.Minute}

// MaxEntries bounds the table (fail closed above it).
const MaxEntries = 65536

// The table is shared by everyone who sends through the node, so nobody
// may take all of it: one peer holds at most MaxPerPeer flows, the node's
// own host stack and LAN together at most MaxLocal. Above that, that
// sender's new flows are dropped and everyone else's still open.
const (
	MaxPerPeer = 8192
	MaxLocal   = 16384
)

// maxSNIBytes bounds what all flows together buffer of ClientHellos that
// arrive in pieces. A flow that would go beyond it is read as one without
// a server name: a permit waiting for the name then aborts it.
const maxSNIBytes = 32 << 20

// Table is the connection table.
type Table struct {
	mu       sync.Mutex
	m        map[Key]*Entry
	t        Timeouts
	onEvent  func(Event)
	learn    Learner
	full     bool
	overflow uint64
	strays   uint64
	perPeer  map[transport.DeviceID]int // flows per principal; "" = local
	sniFree  int                        // bytes still free for split ClientHellos
	// frags: the fragmented packets whose first fragment passed a moment ago
	frags map[fragKey]fragState
}

// fragKey is what the fragments of one IPv4 packet have in common.
type fragKey struct {
	Src, Dst netip.Addr
	Proto    uint8
	ID       uint16
}

type fragState struct {
	e     *Entry
	until time.Time
}

const (
	// fragTTL is how long the rest of a packet may follow its first fragment.
	fragTTL = 10 * time.Second
	// maxFrags bounds the fragment table; above it the rest of new fragmented
	// packets is dropped (fail closed).
	maxFrags = 4096
	// minFragOffset: a later fragment that starts inside the transport header
	// could rewrite the ports the decision was made on (RFC 1858).
	minFragOffset = 24
)

// New creates a table; onEvent may be nil.
func New(t Timeouts, onEvent func(Event)) *Table {
	d := DefaultTimeouts
	if t.TCP == 0 {
		t.TCP = d.TCP
	}
	if t.UDP == 0 {
		t.UDP = d.UDP
	}
	if t.ICMP == 0 {
		t.ICMP = d.ICMP
	}
	if t.Other == 0 {
		t.Other = d.Other
	}
	if t.Closing == 0 {
		t.Closing = d.Closing
	}
	if t.Deny == 0 {
		t.Deny = d.Deny
	}
	if t.Embryonic == 0 {
		t.Embryonic = d.Embryonic
	}
	if onEvent == nil {
		onEvent = func(Event) {}
	}
	return &Table{m: make(map[Key]*Entry), frags: make(map[fragKey]fragState), t: t, onEvent: onEvent,
		perPeer: make(map[transport.DeviceID]int), sniFree: maxSNIBytes}
}

// SetLearner installs the hook for DNS answers (nil switches it off).
func (t *Table) SetLearner(l Learner) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.learn = l
}

// Len returns the number of tracked flows.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// Overflow counts flows refused because the table was full.
// stray: a TCP segment that does not open a connection (no SYN, or the
// SYN+ACK of a handshake the table never saw). Policies decide about it as
// about any first packet, so that a connection survives a reconnect when it
// is permitted; when it is not, there is nothing to report.
func stray(h netparse.Header) bool {
	return h.Proto == netparse.ProtoTCP && h.TCPFlags&(netparse.TCPSyn|netparse.TCPAck) != netparse.TCPSyn
}

// Strays counts denied packets that were not the start of a connection.
func (t *Table) Strays() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.strays
}

func (t *Table) Overflow() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.overflow
}

// Handle classifies one packet. h must be the parsed header of pkt.
func (t *Table) Handle(h netparse.Header, pkt []byte, origin Origin, decide Decider) (Outcome, *Entry) {
	now := time.Now()
	if h.Fragment() {
		return t.fragment(h, len(pkt), now)
	}
	out, e := t.handle(h, pkt, origin, decide, now)
	if out == Pass && e != nil && h.MoreFragments {
		// the first fragment carries the ports and was decided like a whole
		// packet; the others have none and follow it
		t.mu.Lock()
		if len(t.frags) < maxFrags {
			t.frags[fragKey{h.Src, h.Dst, h.Proto, h.FragID}] = fragState{e: e, until: now.Add(fragTTL)}
		}
		t.mu.Unlock()
	}
	return out, e
}

// fragment passes a later fragment of a packet whose first fragment passed.
// It never opens a flow and is never reported: without ports there is
// nothing to decide and nothing to say about it.
func (t *Table) fragment(h netparse.Header, n int, now time.Time) (Outcome, *Entry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.frags[fragKey{h.Src, h.Dst, h.Proto, h.FragID}]
	if !ok || now.After(f.until) || !f.e.Allowed || h.FragOffset < minFragOffset {
		t.strays++
		return Drop, nil
	}
	if !h.MoreFragments {
		delete(t.frags, fragKey{h.Src, h.Dst, h.Proto, h.FragID})
	}
	f.e.LastSeen = now
	f.e.count(netip.AddrPortFrom(h.Src, srcPortOf(f.e, h.Src)), n)
	return Pass, f.e
}

// srcPortOf gives the port a fragment would carry: the one of its flow's end
// with that address.
func srcPortOf(e *Entry, src netip.Addr) uint16 {
	if e.Originator.Addr() == src {
		return e.Originator.Port()
	}
	return e.Target.Port()
}

func (t *Table) handle(h netparse.Header, pkt []byte, origin Origin, decide Decider, now time.Time) (Outcome, *Entry) {
	key := KeyOf(h)
	src := netip.AddrPortFrom(h.Src, h.SrcPort)
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[key]
	if e == nil {
		if rel := t.relatedLocked(h, pkt); rel != nil {
			// an ICMP error about an existing allowed flow passes with it
			rel.LastSeen = now
			return Pass, rel
		}
		limit := MaxPerPeer
		if origin.Local {
			limit = MaxLocal
		}
		if len(t.m) >= MaxEntries || t.perPeer[origin.Principal] >= limit {
			t.overflow++
			return Drop, nil
		}
		e = &Entry{ID: newID(), Key: key, Originator: src, Target: netip.AddrPortFrom(h.Dst, h.DstPort), Proto: h.Proto, Origin: origin, Opened: now, LastSeen: now}
		t.m[key] = e
		t.perPeer[origin.Principal]++
		if !origin.Local && h.Proto == netparse.ProtoUDP && h.DstPort == 53 {
			e.dns, e.Decided = true, true
			return t.dnsPacket(e, h, pkt, src, decide, now)
		}
		e.inspect(h, pkt, src, &t.sniFree)
		if origin.Local {
			e.Allowed = true
			e.count(src, len(pkt))
			t.onEvent(Event{Type: EventOpen, Entry: *e, At: now})
			return Pass, e
		}
		e.Decided = true
		e.decide(decide)
		if !e.Allowed && e.Result.PermitBySNI && h.Proto == netparse.ProtoTCP && !stray(h) {
			e.probing = true
			return Pass, e
		}
		if !e.Allowed {
			e.denyOnly = true
			if stray(h) {
				// the tail of a connection this table no longer knows (closed
				// a moment ago, or from before a reconnect): dropped like any
				// denied packet, but it is no attempt to connect, and logged
				// as one it reads as "the hub was refused access to this Mac"
				t.strays++
				return Drop, e
			}
			t.onEvent(Event{Type: EventDeny, Entry: *e, At: now})
			return Drop, e
		}
		e.count(src, len(pkt))
		t.onEvent(Event{Type: EventOpen, Entry: *e, At: now})
		return Pass, e
	}
	e.LastSeen = now
	if e.dns {
		return t.dnsPacket(e, h, pkt, src, decide, now)
	}
	if e.probing {
		return t.probe(e, h, pkt, src, decide, now)
	}
	if !e.Allowed {
		return Drop, e
	}
	if h.Proto == netparse.ProtoTCP && h.TCPFlags&(netparse.TCPFin|netparse.TCPRst) != 0 {
		e.closing = true
	}
	changed := e.inspect(h, pkt, src, &t.sniFree)
	if changed && e.Decided {
		e.decide(decide)
		if !e.Allowed {
			reset := h.Proto == netparse.ProtoTCP
			t.onEvent(Event{Type: EventDeny, Entry: *e, Reset: reset, At: now})
			e.closing = true
			if reset {
				return Reset, e
			}
			return Drop, e
		}
	}
	e.count(src, len(pkt))
	return Pass, e
}

func (e *Entry) decide(decide Decider) {
	if decide == nil {
		e.Allowed = false
		e.Result = Result{}
		return
	}
	e.Result = decide(e)
	e.Allowed = e.Result.Allow
}

// releaseSNI gives the buffered part of a ClientHello back to the table.
func (e *Entry) releaseSNI(free *int) {
	*free += len(e.sniBuf)
	e.sniBuf = nil
}

// forget takes a removed entry off the table's accounts. t.mu is held.
func (t *Table) forget(e *Entry) {
	e.releaseSNI(&t.sniFree)
	if t.perPeer[e.Origin.Principal] <= 1 {
		delete(t.perPeer, e.Origin.Principal)
	} else {
		t.perPeer[e.Origin.Principal]--
	}
}

func (e *Entry) count(src netip.AddrPort, n int) {
	if src == e.Originator {
		e.PacketsIn++
		e.BytesIn += uint64(n)
	} else {
		e.PacketsOut++
		e.BytesOut += uint64(n)
	}
}

// inspect looks at the first payload from the originator for a TLS server
// name (TCP) or a DNS question (UDP/53). It reports whether an attribute
// was newly learned. free is what the table has left for ClientHellos that
// arrive in pieces.
func (e *Entry) inspect(h netparse.Header, pkt []byte, src netip.AddrPort, free *int) bool {
	if src != e.Originator || h.Payload < 0 || h.Payload >= len(pkt) {
		return false
	}
	payload := pkt[h.Payload:]
	switch h.Proto {
	case netparse.ProtoTCP:
		if e.sniDone {
			return false
		}
		if len(e.sniBuf)+len(payload) > netparse.MaxClientHello || len(payload) > *free {
			e.releaseSNI(free)
			e.sniDone = true
			return false
		}
		*free -= len(payload)
		e.sniBuf = append(e.sniBuf, payload...)
		name, res := netparse.ClientHelloSNI(e.sniBuf)
		switch res {
		case netparse.SNIFound:
			e.releaseSNI(free)
			e.SNI, e.sniDone = name, true
			return true
		case netparse.SNINotTLS, netparse.SNINone:
			e.releaseSNI(free)
			e.sniDone = true
		}
	case netparse.ProtoUDP:
		if e.dnsDone || h.DstPort != 53 {
			return false
		}
		e.dnsDone = true
		if name, ok := netparse.DNSQueryName(payload); ok {
			e.DNSName = name
			return true
		}
	}
	return false
}

// dnsPacket decides one message of a DNS flow from a peer. A resolver
// client keeps one socket for many questions, so the first question does
// not speak for the others: every query is decided under its own name, and
// one that no permit takes is dropped alone (the flow stays for the next).
// What does not read as a query is decided under no name, as plain UDP to
// that address. A response passes only as the answer to a query that
// passed (same message ID, same question), and only such an answer is
// handed to the Learner; anything else from the resolver's side passes only
// when the address itself is permitted.
func (t *Table) dnsPacket(e *Entry, h netparse.Header, pkt []byte, src netip.AddrPort, decide Decider, now time.Time) (Outcome, *Entry) {
	var payload []byte
	if h.Payload >= 0 && h.Payload < len(pkt) {
		payload = pkt[h.Payload:]
	}
	if src != e.Originator {
		if id, ok := netparse.DNSResponseID(payload); ok {
			for i, q := range e.queries {
				if q.id != id {
					continue
				}
				name, addrs, ttl, answered := netparse.DNSAnswer(payload)
				if answered && name != q.name {
					break // another question under the same ID: not this answer
				}
				e.queries = append(e.queries[:i], e.queries[i+1:]...)
				if answered && t.learn != nil {
					t.learn(e, name, addrs, ttl)
				}
				e.count(src, len(pkt))
				return Pass, e
			}
		}
		if e.nameless {
			e.count(src, len(pkt))
			return Pass, e
		}
		return Drop, e
	}

	id, name, query := netparse.DNSQuery(payload)
	first := !e.dnsStarted
	if first {
		e.dnsStarted = true
		// whether the address alone is permitted decides what the other
		// side may send besides answers
		e.DNSName = ""
		e.nameless = decide != nil && decide(e).Allow
	}
	e.DNSName = name
	var res Result
	if decide != nil {
		res = decide(e)
	}
	if !res.Allow {
		if first || name != e.lastDenied {
			d := *e
			d.Allowed, d.Result, d.queries = false, res, nil
			t.onEvent(Event{Type: EventDeny, Entry: d, At: now})
		}
		e.lastDenied = name
		if !e.Allowed {
			e.denyOnly = true
		}
		return Drop, e
	}
	e.lastDenied = ""
	if query {
		if len(e.queries) == maxQueries {
			e.queries = e.queries[1:]
		}
		e.queries = append(e.queries, dnsQuery{id: id, name: name})
	}
	e.Result = res
	e.denyOnly = false
	if !e.Allowed {
		e.Allowed = true
		t.onEvent(Event{Type: EventOpen, Entry: *e, At: now})
	}
	e.count(src, len(pkt))
	return Pass, e
}

// probe handles a packet of a flow that waits for its server name.
func (t *Table) probe(e *Entry, h netparse.Header, pkt []byte, src netip.AddrPort, decide Decider, now time.Time) (Outcome, *Entry) {
	if h.TCPFlags&(netparse.TCPFin|netparse.TCPRst) != 0 {
		e.closing = true
	}
	if h.Payload < 0 || h.Payload >= len(pkt) {
		return Pass, e // the handshake, acknowledgements, the end
	}
	if src == e.Originator {
		e.inspect(h, pkt, src, &t.sniFree)
		if !e.sniDone {
			// a ClientHello split over segments: hold this one back too; the
			// client retransmits it once the name is known and permitted
			return Drop, e
		}
		if e.SNI != "" {
			e.decide(decide)
		}
	}
	// a server that speaks first, no TLS, no name, or a name no permit takes
	e.probing = false
	if e.Allowed {
		e.count(src, len(pkt))
		t.onEvent(Event{Type: EventOpen, Entry: *e, At: now})
		return Pass, e
	}
	e.denyOnly, e.closing = true, true
	t.onEvent(Event{Type: EventDeny, Entry: *e, Reset: true, At: now})
	return Reset, e
}

// relatedLocked finds the allowed flow an ICMP error refers to.
func (t *Table) relatedLocked(h netparse.Header, pkt []byte) *Entry {
	if h.Proto != netparse.ProtoICMP || h.Version != 4 || len(pkt) < 20 {
		return nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+8+20 {
		return nil
	}
	switch pkt[ihl] { // ICMP type: unreachable, source quench, time exceeded, parameter problem
	case 3, 4, 11, 12:
	default:
		return nil // a redirect (5) is never passed on: nobody routes by the overlay's word
	}
	inner, ok := netparse.Parse(pkt[ihl+8:])
	if !ok {
		return nil
	}
	// an error goes back to whoever sent the packet it quotes; to anyone
	// else it would carry a peer's bytes to a host no flow of its reaches
	if h.Dst != inner.Src {
		return nil
	}
	e := t.m[KeyOf(inner)]
	if e == nil || !e.Allowed {
		return nil
	}
	return e
}

// Expire removes idle flows and emits close events.
func (t *Table) Expire(now time.Time) int {
	t.mu.Lock()
	var closed []*Entry
	for k, e := range t.m {
		if now.Sub(e.LastSeen) > t.timeout(e) {
			delete(t.m, k)
			t.forget(e)
			closed = append(closed, e)
		}
	}
	for k, f := range t.frags {
		if now.After(f.until) {
			delete(t.frags, k)
		}
	}
	t.mu.Unlock()
	for _, e := range closed {
		switch {
		case e.Allowed:
			t.onEvent(Event{Type: EventClose, Entry: *e, Reason: "idle", At: now})
		case e.probing:
			t.onEvent(Event{Type: EventDeny, Entry: *e, Reason: "no TLS client hello", At: now})
		}
	}
	return len(closed)
}

func (t *Table) timeout(e *Entry) time.Duration {
	switch {
	case e.denyOnly, e.probing:
		return t.t.Deny
	case e.closing:
		return t.t.Closing
	case e.Proto == netparse.ProtoTCP && e.PacketsOut == 0:
		return t.t.Embryonic
	case e.Proto == netparse.ProtoTCP:
		return t.t.TCP
	case e.Proto == netparse.ProtoUDP:
		return t.t.UDP
	case e.Proto == netparse.ProtoICMP:
		return t.t.ICMP
	}
	return t.t.Other
}

// CloseWhere removes every flow matching pred with the given reason.
func (t *Table) CloseWhere(pred func(*Entry) bool, reason string) int {
	now := time.Now()
	t.mu.Lock()
	var closed []*Entry
	for k, e := range t.m {
		if pred(e) {
			delete(t.m, k)
			t.forget(e)
			closed = append(closed, e)
		}
	}
	t.mu.Unlock()
	for _, e := range closed {
		if e.Allowed {
			t.onEvent(Event{Type: EventClose, Entry: *e, Reason: reason, At: now})
		}
	}
	return len(closed)
}

// Snapshot returns copies of the tracked flows, newest first.
func (t *Table) Snapshot() []Entry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Entry, 0, len(t.m))
	for _, e := range t.m {
		c := *e
		c.sniBuf, c.queries = nil, nil
		out = append(out, c)
	}
	sortEntries(out)
	return out
}

func sortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool { return es[i].Opened.After(es[j].Opened) })
}

func newID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Reevaluate asks decide again for every decided, allowed flow (after a
// policy or session change) and closes the ones that are no longer
// allowed. It returns how many were closed.
func (t *Table) Reevaluate(decide Decider) int {
	now := time.Now()
	t.mu.Lock()
	var denied []*Entry
	for _, e := range t.m {
		if !e.Decided || !e.Allowed {
			continue
		}
		if e.dns {
			// the next query decides itself; what was allowed before must
			// not answer or pass under the old rules
			e.queries = nil
			name := e.DNSName
			e.DNSName = ""
			e.nameless = decide != nil && decide(e).Allow
			e.DNSName = name
		}
		e.decide(decide)
		if !e.Allowed {
			e.denyOnly, e.closing = true, true
			denied = append(denied, e)
		}
	}
	t.mu.Unlock()
	for _, e := range denied {
		t.onEvent(Event{Type: EventDeny, Entry: *e, Reason: "policy changed", At: now})
		t.onEvent(Event{Type: EventClose, Entry: *e, Reason: "policy changed", At: now})
	}
	return len(denied)
}
