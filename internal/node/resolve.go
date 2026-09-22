package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
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
// stay reachable. So a failed lookup keeps the address the name had, said
// once in the log, and the next successful lookup replaces it.
type hosts struct {
	mu     sync.Mutex
	known  map[string]netip.Addr
	stale  map[string]bool
	log    *slog.Logger
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

func newHosts(log *slog.Logger) *hosts {
	return &hosts{known: map[string]netip.Addr{}, stale: map[string]bool{}, log: log,
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		}}
}

// resolve gives the IPv4 address of host (a name or a literal).
func (h *hosts) resolve(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}
	addrs, err := h.lookup(ctx, host)
	if err == nil && len(addrs) == 0 {
		err = errors.New("no address")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err == nil {
		ip := addrs[0].Unmap()
		if h.stale[host] {
			h.log.Info("name resolves again", "host", host, "addr", ip)
			delete(h.stale, host)
		}
		h.known[host] = ip
		return ip, nil
	}
	if ip, ok := h.known[host]; ok {
		if !h.stale[host] {
			h.log.Warn("name lookup failed; using the address it had", "host", host, "addr", ip, "err", err)
			h.stale[host] = true
		}
		return ip, nil
	}
	return netip.Addr{}, fmt.Errorf("resolve %s: %v", host, err)
}

// resolveAddrPort resolves host:port to an address, ports as for UDP.
func (h *hosts) resolveAddrPort(ctx context.Context, hostport string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return ap, nil
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
