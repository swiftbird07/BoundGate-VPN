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
}

// Decider is asked once per new peer-originated flow, and again when an
// inspected attribute (SNI, DNS name) appears.
type Decider func(e *Entry) Result

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

	Opened, LastSeen time.Time
	BytesIn, BytesOut, PacketsIn, PacketsOut uint64 // In = from the originator

	sniBuf   []byte
	sniDone  bool
	dnsDone  bool
	closing  bool
	denyOnly bool // cached deny, expires quickly
}

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

// Timeouts of the table.
type Timeouts struct {
	TCP, UDP, ICMP, Other, Closing, Deny time.Duration
}

// DefaultTimeouts are used when a field is zero.
var DefaultTimeouts = Timeouts{TCP: 30 * time.Minute, UDP: 2 * time.Minute, ICMP: 30 * time.Second, Other: 2 * time.Minute, Closing: 5 * time.Second, Deny: 10 * time.Second}

// MaxEntries bounds the table (fail closed above it).
const MaxEntries = 65536

// Table is the connection table.
type Table struct {
	mu       sync.Mutex
	m        map[Key]*Entry
	t        Timeouts
	onEvent  func(Event)
	full     bool
	overflow uint64
}

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
	if onEvent == nil {
		onEvent = func(Event) {}
	}
	return &Table{m: make(map[Key]*Entry), t: t, onEvent: onEvent}
}

// Len returns the number of tracked flows.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// Overflow counts flows refused because the table was full.
func (t *Table) Overflow() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.overflow
}

// Handle classifies one packet. h must be the parsed header of pkt.
func (t *Table) Handle(h netparse.Header, pkt []byte, origin Origin, decide Decider) (Outcome, *Entry) {
	now := time.Now()
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
		if len(t.m) >= MaxEntries {
			t.overflow++
			return Drop, nil
		}
		e = &Entry{ID: newID(), Key: key, Originator: src, Target: netip.AddrPortFrom(h.Dst, h.DstPort), Proto: h.Proto, Origin: origin, Opened: now, LastSeen: now}
		t.m[key] = e
		e.inspect(h, pkt, src)
		if origin.Local {
			e.Allowed = true
			e.count(src, len(pkt))
			t.onEvent(Event{Type: EventOpen, Entry: *e, At: now})
			return Pass, e
		}
		e.Decided = true
		e.decide(decide)
		if !e.Allowed {
			e.denyOnly = true
			t.onEvent(Event{Type: EventDeny, Entry: *e, At: now})
			return Drop, e
		}
		e.count(src, len(pkt))
		t.onEvent(Event{Type: EventOpen, Entry: *e, At: now})
		return Pass, e
	}
	e.LastSeen = now
	if !e.Allowed {
		return Drop, e
	}
	if h.Proto == netparse.ProtoTCP && h.TCPFlags&(netparse.TCPFin|netparse.TCPRst) != 0 {
		e.closing = true
	}
	changed := e.inspect(h, pkt, src)
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
// was newly learned.
func (e *Entry) inspect(h netparse.Header, pkt []byte, src netip.AddrPort) bool {
	if src != e.Originator || h.Payload < 0 || h.Payload >= len(pkt) {
		return false
	}
	payload := pkt[h.Payload:]
	switch h.Proto {
	case netparse.ProtoTCP:
		if e.sniDone {
			return false
		}
		if len(e.sniBuf)+len(payload) > netparse.MaxClientHello {
			e.sniDone = true
			return false
		}
		e.sniBuf = append(e.sniBuf, payload...)
		name, res := netparse.ClientHelloSNI(e.sniBuf)
		switch res {
		case netparse.SNIFound:
			e.SNI, e.sniDone, e.sniBuf = name, true, nil
			return true
		case netparse.SNINotTLS, netparse.SNINone:
			e.sniDone, e.sniBuf = true, nil
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

// relatedLocked finds the allowed flow an ICMP error refers to.
func (t *Table) relatedLocked(h netparse.Header, pkt []byte) *Entry {
	if h.Proto != netparse.ProtoICMP || h.Version != 4 || len(pkt) < 20 {
		return nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+8+20 {
		return nil
	}
	switch pkt[ihl] { // ICMP type
	case 3, 4, 5, 11, 12:
	default:
		return nil
	}
	inner, ok := netparse.Parse(pkt[ihl+8:])
	if !ok {
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
			closed = append(closed, e)
		}
	}
	t.mu.Unlock()
	for _, e := range closed {
		if e.Allowed {
			t.onEvent(Event{Type: EventClose, Entry: *e, Reason: "idle", At: now})
		}
	}
	return len(closed)
}

func (t *Table) timeout(e *Entry) time.Duration {
	switch {
	case e.denyOnly:
		return t.t.Deny
	case e.closing:
		return t.t.Closing
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
		c.sniBuf = nil
		out = append(out, c)
	}
	sortEntries(out)
	return out
}

func sortEntries(es []Entry) {
	for i := 1; i < len(es); i++ {
		for j := i; j > 0 && es[j].Opened.After(es[j-1].Opened); j-- {
			es[j], es[j-1] = es[j-1], es[j]
		}
	}
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
