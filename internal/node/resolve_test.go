package node

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
)

type fakeNet struct {
	names  map[string][]netip.Addr // "ip" answers
	nat64  []netip.Addr            // ipv4only.arpa
	ipv4   bool                    // the machine has an IPv4 route
	fail   bool                    // lookups fail
	asked  int
}

func (f *fakeNet) hosts() *hosts {
	h := newHosts(slog.Default())
	h.lookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		f.asked++
		if f.fail {
			return nil, errors.New("lookup " + host + ": no such host")
		}
		if host == "ipv4only.arpa" {
			return f.nat64, nil
		}
		return f.names[host], nil
	}
	h.routable = func(a netip.Addr) bool { return !a.Is4() || f.ipv4 }
	return h
}

var (
	v4     = netip.MustParseAddr("136.243.123.200")
	dns64  = netip.MustParseAddr("64:ff9b::88f3:7bc8")
	global = netip.MustParseAddr("2a01:4f8::1")
)

func TestHostsKeepTheLastAddressWhenLookupsFail(t *testing.T) {
	f := &fakeNet{names: map[string][]netip.Addr{"vpn.example": {v4}}, ipv4: true, fail: true}
	h := f.hosts()
	ctx := context.Background()
	if _, err := h.resolve(ctx, "vpn.example"); err == nil {
		t.Fatal("nothing known yet: a failed lookup must fail")
	}
	f.fail = false
	ap, err := h.resolveAddrPort(ctx, "vpn.example:443")
	if err != nil || ap != netip.AddrPortFrom(v4, 443) {
		t.Fatalf("resolve: %v %v", ap, err)
	}
	f.fail = true
	if ip, err := h.resolve(ctx, "vpn.example"); err != nil || ip != v4 || !h.stale["vpn.example"] {
		t.Fatalf("a failed lookup keeps the address it had: %v %v", ip, err)
	}
	f.fail, f.names["vpn.example"] = false, []netip.Addr{netip.MustParseAddr("136.243.123.201")}
	if ip, _ := h.resolve(ctx, "vpn.example"); ip != f.names["vpn.example"][0] || h.stale["vpn.example"] {
		t.Fatal("a lookup that works again replaces the address")
	}
	before := f.asked
	if ip, err := h.resolve(ctx, "10.0.0.1"); err != nil || ip != netip.MustParseAddr("10.0.0.1") || f.asked != before {
		t.Fatal("a routable literal needs no lookup")
	}
}

func TestHostsPreferIPv4WhereItIsRouted(t *testing.T) {
	f := &fakeNet{names: map[string][]netip.Addr{"vpn.example": {global, v4}}, ipv4: true}
	if ip, _ := f.hosts().resolve(context.Background(), "vpn.example"); ip != v4 {
		t.Fatalf("dual stack: %v, want the IPv4 address", ip)
	}
}

// An IPv6-only mobile network: no IPv4 route, DNS64 answers the name with
// a translated address, the NAT64 prefix translates literals and names the
// DNS64 did not answer for (a failed lookup keeps only the IPv4 address).
func TestHostsOnAnIPv6OnlyNetwork(t *testing.T) {
	ctx := context.Background()
	f := &fakeNet{names: map[string][]netip.Addr{"vpn.example": {v4, dns64}}, nat64: []netip.Addr{netip.MustParseAddr("64:ff9b::c000:aa")}}
	h := f.hosts()
	if ip, _ := h.resolve(ctx, "vpn.example"); ip != dns64 {
		t.Fatalf("DNS64 answer: %v", ip)
	}
	ap, _ := h.resolveAddrPort(ctx, "136.243.123.200:443")
	if ap != netip.AddrPortFrom(dns64, 443) {
		t.Fatalf("a literal through NAT64: %v", ap)
	}
	// known only as IPv4 (learned on Wi-Fi), lookups failing now
	f.names["hub.example"] = []netip.Addr{v4}
	f.ipv4 = true
	h.resolve(ctx, "hub.example")
	f.ipv4, f.fail = false, true
	h.networkChanged()
	f.fail = false // ipv4only.arpa answers on the new network
	f.names["hub.example"] = nil
	if ip, _ := h.resolve(ctx, "hub.example"); ip != dns64 {
		t.Fatalf("no answer for the name: the address it had, through NAT64: %v", ip)
	}
	// a network without NAT64 and without IPv4: the IPv4 address, dialing says why
	g := &fakeNet{names: map[string][]netip.Addr{"vpn.example": {v4}}}
	if ip, err := g.hosts().resolve(ctx, "vpn.example"); err != nil || ip != v4 {
		t.Fatalf("no way through: %v %v", ip, err)
	}
}
