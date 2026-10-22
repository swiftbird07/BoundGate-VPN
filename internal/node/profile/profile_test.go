package profile

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func pfx(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s))
	for _, x := range s {
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}

func TestEffectiveNeverExceedsAdvertised(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "work.yaml"), []byte(`
routing:
  mode: include
  networks: [10.60.0.0/24, 10.70.0.0/16, 192.168.0.0/16, 172.16.5.0/24]
`), 0o644)
	ps, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := ps[0]
	if p.Name != "work" || p.Routing.Mode != ModeInclude {
		t.Fatalf("%+v", p)
	}
	adv := pfx("10.60.0.0/16", "10.70.1.0/24", "172.16.0.0/12")
	got := p.Effective(adv)
	// 10.60.0.0/24 ⊆ 10.60.0.0/16 -> want; 10.70.1.0/24 ⊆ 10.70.0.0/16 -> adv;
	// 192.168/16 not advertised -> dropped; 172.16.5.0/24 ⊆ 172.16/12 -> want
	want := pfx("10.60.0.0/24", "10.70.1.0/24", "172.16.5.0/24")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for _, g := range got {
		ok := false
		for _, a := range adv {
			if a.Contains(g.Addr()) && a.Bits() <= g.Bits() {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("%v outside advertised", g)
		}
	}
}

func TestFullModeAndValidation(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "full.yml"), []byte("routing:\n  mode: full\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("routing:\n  mode: include\n"), 0o644)
	p, err := Load(filepath.Join(dir, "full.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "full" {
		t.Fatalf("name %q", p.Name)
	}
	if ps, err := LoadDir(filepath.Join(dir, "missing")); err != nil || ps != nil {
		t.Fatalf("missing dir: %v %v", ps, err)
	}
	if got := p.Effective(pfx("10.0.0.0/8", "10.0.0.0/8")); !reflect.DeepEqual(got, pfx("10.0.0.0/8")) {
		t.Fatalf("%v", got)
	}
	if _, err := Load(filepath.Join(dir, "bad.yaml")); err == nil {
		t.Fatal("include without networks accepted")
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("LoadDir ignored invalid profile")
	}
}

// The two built-ins split "full" between them: what LAN only routes, WAN
// only does not, and together they route every address full routes.
func TestLANAndWANOnlyPartitionFull(t *testing.T) {
	adv := pfx("0.0.0.0/0", "10.20.0.0/16", "192.168.178.0/24", "100.64.0.0/10", "::/0", "fd00:20::/48")
	lan, wan := LANOnly().Effective(adv), WANOnly().Effective(adv)
	for _, l := range lan { // nested routes (10/8 and 10.20/16) are fine: both go into the tunnel
		inside := false
		for _, x := range Private {
			if x := netip.MustParsePrefix(x); x.Bits() <= l.Bits() && x.Contains(l.Addr()) {
				inside = true
			}
		}
		if !inside {
			t.Fatalf("lan-only routes %v, outside the private networks", l)
		}
	}
	for _, w := range wan {
		for _, l := range lan {
			if w.Overlaps(l) {
				t.Fatalf("%v (wan) overlaps %v (lan)", w, l)
			}
		}
		for _, x := range Private {
			if w.Overlaps(netip.MustParsePrefix(x)) {
				t.Fatalf("wan-only routes %v, inside %s", w, x)
			}
		}
	}
	// every address of the advertised default routes is in exactly one of them
	for _, a := range []string{"1.1.1.1", "8.8.8.8", "9.255.255.255", "11.0.0.0", "172.15.255.255", "172.32.0.0", "192.167.1.1", "192.169.0.0", "223.255.255.255", "100.63.255.255", "100.128.0.0", "10.1.2.3", "172.20.0.1", "192.168.178.40", "100.64.0.1", "2001:db8::1", "fd00:20::5"} {
		ip := netip.MustParseAddr(a)
		in := func(ps []netip.Prefix) bool {
			for _, p := range ps {
				if p.Contains(ip) {
					return true
				}
			}
			return false
		}
		if in(lan) == in(wan) {
			t.Fatalf("%s: lan-only %v, wan-only %v; want exactly one", a, in(lan), in(wan))
		}
	}
	// nothing at all from WAN only when the hubs offer no internet
	if got := WANOnly().Effective(pfx("10.20.0.0/16", "192.168.178.0/24")); len(got) != 0 {
		t.Fatalf("wan-only without an exit node: %v", got)
	}
}

func TestExcludeSplitsAroundAndFromAFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "no-home.yaml"), []byte("routing:\n  exclude: [192.168.178.0/24]\n"), 0o644)
	p, err := Load(filepath.Join(dir, "no-home.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Routing.Mode != ModeFull {
		t.Fatalf("exclude alone should mean everything but: %v", p.Routing.Mode)
	}
	got := p.Effective(pfx("192.168.0.0/16", "10.20.0.0/16"))
	// 192.168.0.0/16 around 192.168.178.0/24: .0–.127, .128–.159, .160–.175,
	// .176–.177, .179, .180–.183, .184–.191, .192–.255
	want := pfx("10.20.0.0/16", "192.168.0.0/17", "192.168.128.0/19", "192.168.160.0/20", "192.168.176.0/23", "192.168.179.0/24", "192.168.180.0/22", "192.168.184.0/21", "192.168.192.0/18")
	if !reflect.DeepEqual(got, dedupe(want)) {
		t.Fatalf("got %v", got)
	}
	if p := pfx("10.0.0.0/8")[0]; len(without(p, netip.MustParsePrefix("10.0.0.0/8"))) != 0 || len(without(p, netip.MustParsePrefix("fc00::/7"))) != 1 {
		t.Fatal("without: equal prefixes or another family")
	}
}

// A node's own announced networks come out of what a hub advertises: an
// equal network disappears, a broader one is replaced by the routes around
// it, and a default route among them means nothing.
func TestEffectiveExceptTakesOutOwnNetworks(t *testing.T) {
	full := Full()
	adv := pfx("10.25.0.0/16", "192.168.3.0/24", "0.0.0.0/0")
	own := pfx("192.168.3.0/24")

	got := full.EffectiveExcept(adv, own)
	for _, p := range got {
		if p == netip.MustParsePrefix("192.168.3.0/24") {
			t.Fatalf("the node's own network is still routed: %v", got)
		}
		if p.Contains(netip.MustParseAddr("192.168.3.7")) && p.Bits() > 0 {
			t.Fatalf("%s still covers the node's own network: %v", p, got)
		}
	}
	// the default route is gone as a whole: what is left of it goes around
	// the own network, and the overlay pool stays
	var pool, around bool
	for _, p := range got {
		switch {
		case p == netip.MustParsePrefix("10.25.0.0/16"):
			pool = true
		case p.Bits() > 0 && p.Addr() == netip.MustParseAddr("0.0.0.0"):
			around = true
		}
	}
	if !pool || !around {
		t.Fatalf("pool %v, routes around the own network %v: %v", pool, around, got)
	}

	// a default route of one's own (an exit node) changes nothing
	if a, b := full.EffectiveExcept(adv, pfx("0.0.0.0/0")), full.Effective(adv); !reflect.DeepEqual(a, b) {
		t.Fatalf("a default route of one's own took routes away: %v, want %v", a, b)
	}
	// and nothing extra is the old behaviour
	if a, b := full.EffectiveExcept(adv, nil), full.Effective(adv); !reflect.DeepEqual(a, b) {
		t.Fatalf("without extra networks: %v, want %v", a, b)
	}
}

// An include profile loses only what the node announces itself.
func TestEffectiveExceptWithAnIncludeProfile(t *testing.T) {
	p := &Profile{}
	p.Routing.Mode = ModeInclude
	p.Routing.Networks = []string{"10.20.0.0/16", "192.168.3.0/24"}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	adv := pfx("10.20.0.0/16", "192.168.3.0/24")
	if got, want := p.EffectiveExcept(adv, pfx("192.168.3.0/24")), pfx("10.20.0.0/16"); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
