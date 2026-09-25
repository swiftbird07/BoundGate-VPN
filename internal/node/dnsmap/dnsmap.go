// Package dnsmap remembers which names a peer resolved to which addresses.
// An enforcing node reads the DNS answers it forwards (flow.Learner) and
// keeps, per peer, the names an address was answered with; the ACL then
// decides a later connection to that address under those names, whether or
// not the connection is TLS with a server name (docs/ACL.md).
//
// The map is per peer on purpose: what one device resolved must not open
// anything for another. It is a cache, never a permission — the policies
// still decide, and an entry that expired only means the device has to ask
// again.
package dnsmap

import (
	"net/netip"
	"sync"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

const (
	// MinTTL, MaxTTL bound what an answer's time to live may claim.
	MinTTL = time.Minute
	MaxTTL = time.Hour
	// Grace is added to every entry: resolvers hand out short lives, and a
	// device keeps using an address it looked up a while ago (a connection
	// pool, a browser's own cache).
	Grace = 5 * time.Minute
	// MaxNames bounds the names kept for one address and peer.
	MaxNames = 8
	// fullScan: while the map is full, what expired is looked for at most
	// this often; every answer would otherwise walk the whole map.
	fullScan = 5 * time.Second
)

// key is one peer's view of one address.
type key struct {
	peer transport.DeviceID
	addr netip.Addr
}

// Map is the learned name cache. The zero value is not usable; call New.
type Map struct {
	max, perPeer int

	mu      sync.Mutex
	m       map[key][]entry
	count   map[transport.DeviceID]int // addresses per peer
	scanned time.Time                  // last expiry scan while full
	dropped uint64
}

type entry struct {
	name  string
	until time.Time
}

// New creates a map for at most max addresses over all peers, and an
// eighth of that per peer: one device that resolves a flood of names must
// not push every other device's names out.
func New(limit int) *Map {
	if limit <= 0 {
		limit = 4096
	}
	return &Map{max: limit, perPeer: max(limit/8, 64), m: make(map[key][]entry), count: make(map[transport.DeviceID]int)}
}

// Learn records that name resolved to addrs for this peer. ttl is the
// answer's, clamped to [MinTTL, MaxTTL] plus Grace.
func (m *Map) Learn(peer transport.DeviceID, name string, addrs []netip.Addr, ttl time.Duration, now time.Time) {
	if peer == "" || name == "" || len(addrs) == 0 {
		return
	}
	until := now.Add(min(max(ttl, MinTTL), MaxTTL) + Grace)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range addrs {
		k := key{peer, a.Unmap()}
		es, known := m.m[k]
		if !known && (len(m.m) >= m.max || m.count[peer] >= m.perPeer) {
			if now.Sub(m.scanned) >= fullScan {
				m.scanned = now
				m.expireLocked(now)
			}
			if es, known = m.m[k]; !known && (len(m.m) >= m.max || m.count[peer] >= m.perPeer) {
				m.dropped++
				continue
			}
		}
		if !known {
			m.count[peer]++
		}
		found := false
		for i := range es {
			if es[i].name == name {
				es[i].until, found = until, true
				break
			}
		}
		if !found {
			if len(es) >= MaxNames {
				es = es[1:] // the oldest name of this address gives way
			}
			es = append(es, entry{name: name, until: until})
		}
		m.m[k] = es
	}
}

// Names returns the names this peer resolved to addr, newest last. The
// result is a fresh slice; an expired name is not returned.
func (m *Map) Names(peer transport.DeviceID, addr netip.Addr, now time.Time) []string {
	if peer == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	es := m.m[key{peer, addr.Unmap()}]
	var out []string
	for _, e := range es {
		if now.Before(e.until) {
			out = append(out, e.name)
		}
	}
	return out
}

// Expire drops what has run out.
func (m *Map) Expire(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(now)
}

func (m *Map) expireLocked(now time.Time) {
	for k, es := range m.m {
		keep := es[:0]
		for _, e := range es {
			if now.Before(e.until) {
				keep = append(keep, e)
			}
		}
		if len(keep) == 0 {
			delete(m.m, k)
			if m.count[k.peer]--; m.count[k.peer] <= 0 {
				delete(m.count, k.peer)
			}
			continue
		}
		m.m[k] = keep
	}
}

// Len is the number of addresses the map holds, Dropped how many it had to
// refuse because it was full.
func (m *Map) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.m)
}

func (m *Map) Dropped() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropped
}
