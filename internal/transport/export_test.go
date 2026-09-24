package transport

import "time"

// SetLiveness shortens the liveness check for tests; it returns a function
// that restores the defaults.
func SetLiveness(for_ time.Duration, writes int64) func() {
	oldFor, oldWrites := silentFor, silentWrites
	silentFor, silentWrites = for_, writes
	return func() { silentFor, silentWrites = oldFor, oldWrites }
}
