package api

import "time"

// ResetRateLimitsForTest empties the per-address buckets, so a test that
// plays many attackers from 127.0.0.1 is not stopped by the limiter (which
// has its own test).
func (h *Handlers) ResetRateLimitsForTest() {
	h.limit = newRateLimiter(5, time.Minute)
	h.signLimit = newRateLimiter(30, time.Minute)
	h.loginLimit = newRateLimiter(10, time.Minute)
}

// LocalPathForTest exposes the check of an admin login's next= target.
func LocalPathForTest(next string) string { return localPath(next) }
