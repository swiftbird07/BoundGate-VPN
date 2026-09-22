package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
)

// hosts is the node's address book: what the names of the control plane,
// the hubs, peers and the identity provider resolved to. The node dials
// those addresses, not the names, because they are what it keeps outside
// its own tunnel (the bypass routes): a name that resolved differently a
// moment later would be routed through the tunnel. And a name lookup is not
// always possible once the tunnel is up: inside an iOS packet tunnel
// provider the system resolver answers "no such host" for everything after
// the tunnel's DNS settings took effect, while the addresses learned before
// stay reachable. So a failed lookup keeps the addresses the name had, said
// once in the log, and the next successful lookup replaces them.
//
// Of the addresses a name has, the node dials the first the machine has a
// route for, IPv4 first. On an IPv6-only network (many mobile networks)
// there is no IPv4 route at all: dialing an IPv4 address fails at once with
// "network is unreachable". There the network's DNS64 answers the name with
// an IPv6 address that its NAT64 translates, and an IPv4 address (a literal,
// or a name without such an answer) is translated by the node itself with
// the NAT64 prefix the network announces (RFC 7050: ipv4only.arpa).
type hosts struct {
	mu    sync.Mutex
	known map[string][]netip.Addr
	stale map[string]bool
	log   *slog.Logger
	// nat64 is the prefix of this network, learned on demand; checked is
	// set once it was asked for (a network without NAT64 has none)
	nat64   netip.Prefix
	checked bool

	lookup   func(ctx context.Context, network, host string) ([]netip.Addr, error)
	routable func(netip.Addr) bool
}

func newHosts(log *slog.Logger) *hosts {
	return &hosts{known: map[string][]netip.Addr{}, stale: map[string]bool{}, log: log,
		lookup:   net.DefaultResolver.LookupNetIP,
		routable: hasRoute,
	}
}

// hasRoute reports whether the machine has a route to a: connecting a UDP
// socket looks the route up and sends nothing.
func hasRoute(a netip.Addr) bool {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, 443)))
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// networkChanged forgets what belongs to the network the machine left.
func (h *hosts) networkChanged() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nat64, h.checked = netip.Prefix{}, false
}

// resolve gives the address to dial for host (a name or a literal).
func (h *hosts) resolve(ctx context.Context, host string) (netip.Addr, error) {
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip.Unmap()}
	} else {
		if addrs, err = h.names(ctx, host); err != nil {
			return netip.Addr{}, err
		}
	}
	for _, a := range addrs {
		if h.routable(a) {
			return a, nil
		}
	}
	// no route for any of them: an IPv6-only network, if it translates
	for _, a := range addrs {
		if !a.Is4() {
			continue
		}
		if s, ok := h.synthesize(ctx, a); ok && h.routable(s) {
			return s, nil
		}
	}
	// dialing says why it does not work
	return addrs[0], nil
}

// names looks host up, IPv4 addresses first; a failed lookup keeps what
// the name had.
func (h *hosts) names(ctx context.Context, host string) ([]netip.Addr, error) {
	found, err := h.lookup(ctx, "ip", host)
	var addrs []netip.Addr
	for _, a := range found {
		a = a.Unmap()
		if !slices.Contains(addrs, a) {
			addrs = append(addrs, a)
		}
	}
	slices.SortStableFunc(addrs, func(a, b netip.Addr) int {
		switch {
		case a.Is4() && !b.Is4():
			return -1
		case !a.Is4() && b.Is4():
			return 1
		}
		return 0
	})
	if err == nil && len(addrs) == 0 {
		err = errors.New("no address")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err == nil {
		if h.stale[host] {
			h.log.Info("name resolves again", "host", host, "addrs", addrs)
			delete(h.stale, host)
		}
		h.known[host] = addrs
		return addrs, nil
	}
	if old, ok := h.known[host]; ok {
		if !h.stale[host] {
			h.log.Warn("name lookup failed; using the addresses it had", "host", host, "addrs", old, "err", err)
			h.stale[host] = true
		}
		return old, nil
	}
	return nil, fmt.Errorf("resolve %s: %v", host, err)
}

// wellKnown are the IPv4 addresses of ipv4only.arpa (RFC 7050).
var wellKnown = [][4]byte{{192, 0, 0, 170}, {192, 0, 0, 171}}

// synthesize translates an IPv4 address with this network's NAT64 prefix.
// Only /96 prefixes (the well-known 64:ff9b::/96 and most operators') are
// used: the other lengths of RFC 6052 split the address around a reserved
// octet and are rare enough to say so instead.
func (h *hosts) synthesize(ctx context.Context, a netip.Addr) (netip.Addr, bool) {
	h.mu.Lock()
	checked, prefix := h.checked, h.nat64
	h.mu.Unlock()
	if !checked {
		found, err := h.lookup(ctx, "ip6", "ipv4only.arpa")
		prefix = netip.Prefix{}
		for _, s := range found {
			b := s.As16()
			for _, w := range wellKnown {
				if [4]byte(b[12:16]) == w {
					prefix = netip.PrefixFrom(s, 96).Masked()
				}
			}
		}
		if err == nil && len(found) > 0 && !prefix.IsValid() {
			h.log.Warn("this network's NAT64 prefix is not a /96; IPv4-only hosts are not reachable from here", "ipv4only.arpa", found)
		}
		h.mu.Lock()
		h.nat64, h.checked = prefix, true
		h.mu.Unlock()
		if prefix.IsValid() {
			h.log.Info("IPv6-only network with NAT64: IPv4 addresses are dialed through it", "prefix", prefix)
		}
	}
	if !prefix.IsValid() {
		return netip.Addr{}, false
	}
	b := prefix.Addr().As16()
	copy(b[12:], a.AsSlice())
	return netip.AddrFrom16(b), true
}

// resolveAddrPort resolves host:port to an address, ports as for UDP.
func (h *hosts) resolveAddrPort(ctx context.Context, hostport string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		ip, err := h.resolve(ctx, ap.Addr().String())
		if err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(ip, ap.Port()), nil
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("address %q: %w", hostport, err)
	}
	ip, err := h.resolve(ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	p, err := net.LookupPort("udp", port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, uint16(p)), nil
}
