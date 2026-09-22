package node

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
)

func TestHostsKeepTheLastAddressWhenLookupsFail(t *testing.T) {
	answer, fail := []netip.Addr{netip.MustParseAddr("136.243.123.200")}, true
	calls := 0
	h := newHosts(slog.Default())
	h.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		calls++
		if fail {
			return nil, errors.New("lookup " + host + ": no such host")
		}
		return answer, nil
	}
	ctx := context.Background()
	if _, err := h.resolve(ctx, "vpn.example"); err == nil || calls != 1 {
		t.Fatal("nothing known yet: a failed lookup must fail")
	}
	fail = false
	ap, err := h.resolveAddrPort(ctx, "vpn.example:443")
	if err != nil || ap != netip.MustParseAddrPort("136.243.123.200:443") {
		t.Fatalf("resolve: %v %v", ap, err)
	}
	fail = true
	ip, err := h.resolve(ctx, "vpn.example")
	if err != nil || ip != answer[0] || !h.stale["vpn.example"] {
		t.Fatalf("a failed lookup keeps the address it had: %v %v", ip, err)
	}
	fail, answer = false, []netip.Addr{netip.MustParseAddr("136.243.123.201")}
	if ip, _ := h.resolve(ctx, "vpn.example"); ip != answer[0] || h.stale["vpn.example"] {
		t.Fatal("a lookup that works again replaces the address")
	}
	if ip, err := h.resolve(ctx, "10.0.0.1"); err != nil || ip != netip.MustParseAddr("10.0.0.1") || calls != 4 {
		t.Fatal("a literal address needs no lookup")
	}
}
