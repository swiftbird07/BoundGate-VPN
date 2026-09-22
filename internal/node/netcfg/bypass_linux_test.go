//go:build linux

package netcfg

import "testing"

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
