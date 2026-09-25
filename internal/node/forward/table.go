package forward

import (
	"net/netip"
	"sort"
	"sync"
)

// Table maps destination addresses to tunnels: exact overlay addresses
// first, then the longest matching announced prefix.
//
// An announced prefix never takes what belongs to this node: an address in
// the overlay pool is reached only through the tunnel that owns it (its
// host entry), and an address in a network this node announces itself goes
// to the host stack unless a peer announces a more specific part of it. An
// exit node's 0.0.0.0/0 would otherwise catch the hub's own overlay
// address, its LAN, and every peer the hub does not carry, and could answer
// for them.
type Table struct {
	mu       sync.RWMutex
	hosts    map[netip.Addr]PacketWriter
	prefixes []prefixEntry // sorted by prefix length, longest first
	pool     netip.Prefix
	own      []netip.Prefix
}

type prefixEntry struct {
	prefix netip.Prefix
	pw     PacketWriter
}

// NewTable creates an empty table.
func NewTable() *Table {
	return &Table{hosts: make(map[netip.Addr]PacketWriter)}
}

// Attach registers pw as the owner of addr.
func (t *Table) Attach(addr netip.Addr, pw PacketWriter) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hosts[addr] = pw
}

// Detach removes addr if it is still owned by pw.
func (t *Table) Detach(addr netip.Addr, pw PacketWriter) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if cur, ok := t.hosts[addr]; ok && cur == pw {
		delete(t.hosts, addr)
	}
}

// AttachPrefix registers pw for a prefix. Several writers may announce the
// same prefix (HA subnet routers); the first attached one is used until it
// detaches.
func (t *Table) AttachPrefix(p netip.Prefix, pw PacketWriter) {
	p = p.Masked()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.prefixes {
		if e.prefix == p && e.pw == pw {
			return
		}
	}
	t.prefixes = append(t.prefixes, prefixEntry{prefix: p, pw: pw})
	sort.SliceStable(t.prefixes, func(i, j int) bool { return t.prefixes[i].prefix.Bits() > t.prefixes[j].prefix.Bits() })
}

// DetachPrefix removes pw's entry for p and reports whether another writer
// still serves the prefix.
func (t *Table) DetachPrefix(p netip.Prefix, pw PacketWriter) (stillServed bool) {
	p = p.Masked()
	t.mu.Lock()
	defer t.mu.Unlock()
	kept := t.prefixes[:0]
	for _, e := range t.prefixes {
		if e.prefix == p && e.pw == pw {
			continue
		}
		if e.prefix == p {
			stillServed = true
		}
		kept = append(kept, e)
	}
	t.prefixes = kept
	return stillServed
}

// SetReserved names what no announced prefix may take: the overlay pool
// and the networks this node announces itself.
func (t *Table) SetReserved(pool netip.Prefix, own []netip.Prefix) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pool = pool.Masked()
	t.own = make([]netip.Prefix, len(own))
	for i, p := range own {
		t.own[i] = p.Masked()
	}
}

// Lookup returns the writer for dst: the exact host entry, else the longest
// matching prefix that is not reserved (SetReserved).
func (t *Table) Lookup(dst netip.Addr) (PacketWriter, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if pw, ok := t.hosts[dst]; ok {
		return pw, true
	}
	if t.pool.IsValid() && t.pool.Contains(dst) {
		return nil, false
	}
	floor := -1 // an announced prefix must be longer than this to win
	for _, o := range t.own {
		if o.Contains(dst) && o.Bits() > floor {
			floor = o.Bits()
		}
	}
	for _, e := range t.prefixes {
		if e.prefix.Bits() <= floor {
			return nil, false // the rest is shorter still
		}
		if e.prefix.Contains(dst) {
			return e.pw, true
		}
	}
	return nil, false
}

// Hosts returns the number of attached host entries.
func (t *Table) Hosts() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.hosts)
}
