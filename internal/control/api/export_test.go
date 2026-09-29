package api

import (
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// ResetRateLimitsForTest empties the per-address buckets, so a test that
// plays many attackers from 127.0.0.1 is not stopped by the limiter (which
// has its own test).
func (h *Handlers) ResetRateLimitsForTest() {
	h.limit = newRateLimiter(5, time.Minute)
	h.signLimit = newRateLimiter(30, time.Minute)
	h.loginLimit = newRateLimiter(10, time.Minute)
	h.shipLimit = newRateLimiter(ShipBatchesPerMinute, time.Minute)
}

// LocalPathForTest exposes the check of an admin login's next= target.
func LocalPathForTest(next string) string { return localPath(next) }

// SetLookupForTest replaces the device lookup, so a test can play a registry
// that cannot be asked at all (a database that is busy, locked or gone).
func (h *Handlers) SetLookupForTest(l transport.DeviceLookup) { h.lookup = l }
