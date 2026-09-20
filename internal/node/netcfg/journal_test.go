package netcfg

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

type fakeCfg struct{ calls []string }

func (f *fakeCfg) CreateTUN(string, int) (tun.Device, string, error)           { return nil, "", ErrUnsupported }
func (f *fakeCfg) SetAddress(context.Context, string, netip.Prefix, int) error { return nil }
func (f *fakeCfg) AddRoute(_ context.Context, d netip.Prefix, i string) error {
	f.calls = append(f.calls, "add "+d.String()+" "+i)
	return nil
}
func (f *fakeCfg) DelRoute(_ context.Context, d netip.Prefix, i string) error {
	f.calls = append(f.calls, "del "+d.String()+" "+i)
	return nil
}
func (f *fakeCfg) AddBypass(_ context.Context, h netip.Addr) error {
	f.calls = append(f.calls, "bypass "+h.String())
	return nil
}
func (f *fakeCfg) DelBypass(_ context.Context, h netip.Addr) error {
	f.calls = append(f.calls, "unbypass "+h.String())
	return nil
}
func (f *fakeCfg) EnableForwarding(context.Context) error { return nil }

func (f *fakeCfg) AllowForward(context.Context, string, bool) (bool, error) { return false, nil }
func (f *fakeCfg) SetNAT(_ context.Context, _ netip.Prefix, d []netip.Prefix, i string) error {
	if len(d) == 0 {
		f.calls = append(f.calls, "nat-off "+i)
	}
	return nil
}

func TestJournalRecoversLeftovers(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "netstate.json")
	first := &fakeCfg{}
	j := NewJournal(first, path)
	lan, pool := netip.MustParsePrefix("10.60.0.0/24"), netip.MustParsePrefix("10.21.0.0/16")
	hub, cpl := netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("203.0.113.9")
	j.AddRoute(ctx, pool, "utun4")
	j.AddRoute(ctx, lan, "utun4")
	j.AddRoute(ctx, lan, "utun4") // idempotent
	j.AddBypass(ctx, hub)
	j.AddBypass(ctx, cpl)
	j.SetNAT(ctx, pool, []netip.Prefix{lan}, "bg0")
	j.DelRoute(ctx, lan, "utun4") // cleaned up properly: not a leftover
	j.DelBypass(ctx, cpl)
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}

	// the process dies here; the next one recovers
	second := &fakeCfg{}
	j2 := NewJournal(second, path)
	if n := j2.Recover(ctx); n != 3 {
		t.Fatalf("recovered %d entries, calls %v", n, second.calls)
	}
	sort.Strings(second.calls)
	want := []string{"del 10.21.0.0/16 utun4", "nat-off bg0", "unbypass 203.0.113.7"}
	if !reflect.DeepEqual(second.calls, want) {
		t.Fatalf("calls %v want %v", second.calls, want)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("state file survived recovery")
	}
	if n := j2.Recover(ctx); n != 0 {
		t.Fatal("second recovery found something")
	}

	// a clean shutdown leaves no file
	j3 := NewJournal(&fakeCfg{}, path)
	j3.AddBypass(ctx, hub)
	j3.DelBypass(ctx, hub)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("state file left after a clean teardown")
	}
	// garbage in the file is discarded
	os.WriteFile(path, []byte("{nope"), 0o600)
	if n := NewJournal(&fakeCfg{}, path).Recover(ctx); n != 0 {
		t.Fatal("garbage recovered")
	}
}

func TestDarwinCommands(t *testing.T) {
	if got := darwinTUNName("bg0"); got != "utun" {
		t.Fatal(got)
	}
	if got := darwinTUNName("utun7"); got != "utun7" {
		t.Fatal(got)
	}
	a := darwinAddrArgs("utun4", netip.MustParsePrefix("10.21.0.5/16"), 1280)
	if want := []string{"ifconfig", "utun4", "inet", "10.21.0.5", "10.21.0.5", "netmask", "255.255.255.255", "mtu", "1280", "up"}; !reflect.DeepEqual(a, want) {
		t.Fatalf("%v", a)
	}
	r := darwinRouteArgs("add", netip.MustParsePrefix("10.60.0.9/24"), "utun4")
	if want := []string{"route", "-n", "add", "-inet", "-net", "10.60.0.0/24", "-interface", "utun4"}; !reflect.DeepEqual(r, want) {
		t.Fatalf("%v", r)
	}
	// a routed destination: via the gateway
	gw, err := parseDarwinRouteGet("   route to: 203.0.113.7\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n")
	if err != nil || gw.Gateway != "192.168.1.1" || gw.Iface != "en0" {
		t.Fatalf("%+v %v", gw, err)
	}
	host := netip.MustParseAddr("203.0.113.7")
	if got := darwinBypassArgs("add", host, gw); !reflect.DeepEqual(got, []string{"route", "-n", "add", "-inet", "-host", "203.0.113.7", "192.168.1.1"}) {
		t.Fatalf("%v", got)
	}
	// an on-link destination: no IP gateway, route by interface
	link, _ := parseDarwinRouteGet("   route to: 192.168.1.20\ndestination: 192.168.1.20\n  interface: en0\n")
	if got := darwinBypassArgs("add", netip.MustParseAddr("192.168.1.20"), link); !reflect.DeepEqual(got, []string{"route", "-n", "add", "-inet", "-host", "192.168.1.20", "-interface", "en0"}) {
		t.Fatalf("%v", got)
	}
	if got := darwinBypassArgs("delete", host, darwinRoute{}); !reflect.DeepEqual(got, []string{"route", "-n", "delete", "-inet", "-host", "203.0.113.7"}) {
		t.Fatalf("%v", got)
	}
	if _, err := parseDarwinRouteGet("route: writing to routing socket: not in table\n"); err == nil {
		t.Fatal("no interface accepted")
	}
}
