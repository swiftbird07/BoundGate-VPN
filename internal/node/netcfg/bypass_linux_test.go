//go:build linux

package netcfg

import (
	"net/netip"
	"strings"
	"testing"
)

// A host route renewed under a full-tunnel profile goes out by the default
// route with the lowest metric, never by the node's own device.
func TestLinuxDefaultRoute(t *testing.T) {
	own := func(d string) bool { return d == "bg0" }
	out := []byte(`[{"dst":"default","gateway":"192.168.1.1","dev":"wlan0","metric":600},
		{"dst":"default","dev":"bg0","metric":0},
		{"dst":"default","gateway":"10.0.0.1","dev":"eth0","metric":100}]`)
	r, err := linuxDefaultRoute(out, own)
	if err != nil || r.Dev != "eth0" || r.Gateway != "10.0.0.1" {
		t.Fatalf("got %+v, %v", r, err)
	}
	if _, err := linuxDefaultRoute([]byte(`[{"dst":"default","dev":"bg0"}]`), own); err == nil {
		t.Fatal("only the tunnel: accepted")
	}
	if _, err := linuxDefaultRoute([]byte(`[]`), own); err == nil {
		t.Fatal("no default route: accepted")
	}
}

// A gateway the interface does not have in any of its prefixes is reached
// onlink: that is how a routed segment looks (the whole LAN through a
// router), and without the flag the kernel refuses the route.
func TestBypassArgsSaysOnlinkForAGatewayOutsideTheSubnet(t *testing.T) {
	host := netip.MustParseAddr("136.243.123.200")
	for _, c := range []struct {
		name   string
		r      routeGet
		onLink bool
		want   string
	}{
		{"gateway in the subnet", routeGet{Dev: "eth0", Gateway: "10.0.0.1"}, true,
			"ip route replace 136.243.123.200/32 dev eth0 via 10.0.0.1"},
		{"gateway outside it", routeGet{Dev: "ens18", Gateway: "10.20.0.1"}, false,
			"ip route replace 136.243.123.200/32 dev ens18 via 10.20.0.1 onlink"},
		{"no gateway at all", routeGet{Dev: "eth0"}, false,
			"ip route replace 136.243.123.200/32 dev eth0"},
	} {
		if got := strings.Join(bypassArgs(host, c.r, c.onLink), " "); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// onLink reads the device's addresses; loopback carries 127.0.0.1/8 on every
// machine this test runs on.
func TestOnLink(t *testing.T) {
	if !onLink("lo", "127.0.0.2") {
		t.Error("127.0.0.2 on lo: not on-link")
	}
	if onLink("lo", "10.20.0.1") {
		t.Error("10.20.0.1 on lo: on-link")
	}
	if onLink("nosuchdev0", "10.20.0.1") {
		t.Error("a device that does not exist: on-link")
	}
	if onLink("lo", "") {
		t.Error("no gateway: on-link")
	}
}
