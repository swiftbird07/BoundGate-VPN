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
}

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
func (l *rateLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	refill := now.Sub(b.last).Seconds() / l.per.Seconds() * l.burst
	b.tokens = min(l.burst, b.tokens+refill)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	// keep the map bounded
	if len(l.buckets) > 10000 {
		for k, v := range l.buckets {
			if now.Sub(v.last) > l.per {
				delete(l.buckets, k)
			}
		}
	}
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
