package api

import (
	"sync"
	"time"
)

// rateLimiter is a small per-key token bucket for the unauthenticated
// enrollment endpoint.
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
