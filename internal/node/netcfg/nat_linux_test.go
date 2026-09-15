//go:build linux

package netcfg

import (
	"net/netip"
	"strings"
	"testing"
)

func TestNATRules(t *testing.T) {
	pool := netip.MustParsePrefix("10.21.0.0/16")
	got := NATRules(pool, []netip.Prefix{netip.MustParsePrefix("192.168.178.0/24"), netip.MustParsePrefix("0.0.0.0/0")}, "bg0")
	want := []string{
		`ip saddr 10.21.0.0/16 ip daddr 192.168.178.0/24 oifname != "bg0" masquerade`,
		`ip saddr 10.21.0.0/16 oifname != "bg0" masquerade`,
		`type nat hook postrouting priority srcnat`,
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Fatalf("rules lack %q:\n%s", w, got)
		}
	}
}
