package api

import (
	"net/netip"
	"sync"
	"time"
)

// rateLimiter is a small per-key token bucket for the unauthenticated
// endpoints (enrollment, sign tokens, admin login) and for per-node limits.
type rateLimiter struct {
	mu      sync.Mutex
	burst   float64
	per     time.Duration
	buckets map[string]*bucket
	swept   time.Time // when idle buckets were last dropped
}

// maxBuckets bounds what the limiter remembers: beyond it, a client it has
// not seen is refused rather than given memory. One bucket per fresh
// address (a /64 for IPv6) is what a flood from a large allocation costs.
const maxBuckets = 50000

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(burst int, per time.Duration) *rateLimiter {
	return &rateLimiter{burst: float64(burst), per: per, buckets: make(map[string]*bucket)}
}

// allowClient is allow for a client address: see clientKey.
func (l *rateLimiter) allowClient(ip string) bool { return l.allow(clientKey(ip)) }

// allow reports whether key may proceed and consumes a token if so.
func (l *rateLimiter) allow(key string) bool { return l.allowN(key, 1) }

// allowN is allow for n tokens at once: bytes of a request, for a limiter
// whose burst is a number of bytes.
func (l *rateLimiter) allowN(key string, n float64) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// keep the map bounded: idle buckets go, at most once a second (the
	// sweep walks the whole map), and beyond the cap no new one is made
	if len(l.buckets) > 10000 && now.Sub(l.swept) > time.Second {
		l.swept = now
		for k, v := range l.buckets {
			if now.Sub(v.last) > l.per {
				delete(l.buckets, k)
			}
		}
	}
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxBuckets {
			return false
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	refill := now.Sub(b.last).Seconds() / l.per.Seconds() * l.burst
	b.tokens = min(l.burst, b.tokens+refill)
	b.last = now
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// clientKey is what a per-client limit counts: the address for IPv4, the
// /64 for IPv6, where one host usually has a whole /64 to pick addresses
// from.
func clientKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	return p.String()
}

// sameClientNetwork reports whether two client addresses count as the same
// client (clientKey).
func sameClientNetwork(a, b string) bool { return clientKey(a) == clientKey(b) }
