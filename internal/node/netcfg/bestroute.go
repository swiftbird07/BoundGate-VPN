package netcfg

import "net/netip"

// routeEntry is one row of a routing table, reduced to what choosing a path
// needs (Windows reads it from GetIpForwardTable2).
type routeEntry struct {
	Dst     netip.Prefix
	NextHop netip.Addr // unspecified: on-link
	IfIndex uint32
	// Metric is the route metric plus the interface metric: what the stack
	// compares between routes of the same length.
	Metric uint32
}

// bestRoute picks the route the stack would take to host, ignoring the
// interfaces in skip (the tunnel itself): the longest matching prefix, then
// the lowest metric. ok is false when nothing leads there.
func bestRoute(table []routeEntry, host netip.Addr, skip map[uint32]bool) (best routeEntry, ok bool) {
	for _, r := range table {
		if skip[r.IfIndex] || !r.Dst.Contains(host) {
			continue
		}
		if !ok || r.Dst.Bits() > best.Dst.Bits() || r.Dst.Bits() == best.Dst.Bits() && r.Metric < best.Metric {
			best, ok = r, true
		}
	}
	return best, ok
}
