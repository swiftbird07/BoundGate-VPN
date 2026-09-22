package netcfg

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// What the Watchers of the daemons (Linux, macOS, Windows) have in common:
// the operating system reports that something in its routing changed (a
// netlink message, a routing socket message, an IP Helper callback), and
// that happens all the time: containers come and go, ARP entries are cloned,
// the node sets its own routes. What matters to the host routes of control
// plane and hubs is one thing only: the machine's default routes outside the
// tunnel. So an event only starts a look at them, at most every
// watchDelay, and changed runs when they differ from the last look.

// watchDelay: how long a burst of events is collected before the default
// routes are compared (Windows and Linux report one change several times).
var watchDelay = 2 * time.Second

// watchDefaults runs until ctx ends. events carries one token per burst
// (producers send without blocking into a channel of size 1); snapshot
// describes the current default routes outside the tunnel.
func watchDefaults(ctx context.Context, events <-chan struct{}, snapshot func() (string, error), changed func()) {
	last, _ := snapshot()
	t := time.NewTimer(0)
	<-t.C
	for {
		select {
		case <-ctx.Done():
			return
		case <-events:
		}
		// no reset per event: a steady stream of events must not starve the check
		t.Reset(watchDelay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		select { // the burst we waited for
		case <-events:
		default:
		}
		cur, err := snapshot()
		if err != nil || cur == last {
			continue
		}
		last = cur
		changed()
	}
}

// notify sends a token without blocking: one pending token is enough.
func notify(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// ownIfaces remembers the tunnel devices this configurator created: their
// routes are the node's own and never a reason to renew anything.
type ownIfaces struct {
	mu    sync.Mutex
	names map[string]bool
}

func (o *ownIfaces) add(name string) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.names == nil {
		o.names = map[string]bool{}
	}
	o.names[name] = true
}

func (o *ownIfaces) has(name string) bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.names[name]
}

// sortedLines joins lines in a stable order, so that a table read in another
// order is the same snapshot.
func sortedLines(lines []string) string {
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// linuxDefaults extracts the default routes from /proc/net/route and
// /proc/net/ipv6_route: interface, gateway, metric; routes over skip
// (the node's own devices) and "lo" (the kernel's unreachable IPv6 default)
// left out.
func linuxDefaults(route4, route6 string, skip func(string) bool) string {
	var out []string
	for i, line := range strings.Split(route4, "\n") {
		f := strings.Fields(line)
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		if i == 0 || len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" || skip(f[0]) {
			continue
		}
		out = append(out, "4 "+f[0]+" "+f[2]+" "+f[6])
	}
	for _, line := range strings.Split(route6, "\n") {
		f := strings.Fields(line)
		// dst dst_len src src_len nexthop metric refcnt use flags iface
		if len(f) < 10 || f[1] != "00" || strings.Trim(f[0], "0") != "" || f[9] == "lo" || skip(f[9]) {
			continue
		}
		out = append(out, "6 "+f[9]+" "+f[4]+" "+f[5])
	}
	return sortedLines(out)
}

// darwinDefaults extracts the default routes from `netstat -rn` output:
// gateway and interface (the flags change with use and are left out).
func darwinDefaults(netstat string, skip func(string) bool) string {
	var out []string
	for _, line := range strings.Split(netstat, "\n") {
		f := strings.Fields(line)
		// Destination Gateway Flags Netif [Expire]
		if len(f) < 4 || f[0] != "default" || skip(f[3]) {
			continue
		}
		out = append(out, f[1]+" "+f[3])
	}
	return sortedLines(out)
}
