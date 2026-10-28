package netcfg

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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

// dnsCfg is a configurator that can point the host's resolver somewhere.
// offErr makes giving it back fail, as a Mac whose scutil was cut off does.
type dnsCfg struct {
	fakeCfg
	dns    map[string][]netip.Addr
	offErr error
	offs   int
}

func (d *dnsCfg) SetLinkDNS(_ context.Context, ifname string, servers []netip.Addr) error {
	if d.dns == nil {
		d.dns = map[string][]netip.Addr{}
	}
	if len(servers) == 0 {
		d.offs++
		if d.offErr != nil {
			return d.offErr
		}
		delete(d.dns, ifname)
		d.calls = append(d.calls, "dns-off "+ifname)
		return nil
	}
	d.dns[ifname] = servers
	d.calls = append(d.calls, "dns "+ifname)
	return nil
}

// A node that died with the host's resolver pointed into its tunnel gives it
// back on the next start.
func TestJournalGivesTheResolverBack(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "netstate.json")
	first := &dnsCfg{}
	j := NewJournal(first, path)
	if _, ok := LinkDNS(j); !ok {
		t.Fatal("LinkDNS does not see through the journal")
	}
	if err := j.SetLinkDNS(ctx, "bg0", []netip.Addr{netip.MustParseAddr("10.20.0.1")}); err != nil {
		t.Fatal(err)
	}
	if len(first.dns["bg0"]) != 1 {
		t.Fatalf("the resolver was not set: %+v", first.dns)
	}

	// the process dies here: a second one reads the journal
	second := &dnsCfg{}
	if n := NewJournal(second, path).Recover(ctx); n != 1 {
		t.Fatalf("recovered %d entries", n)
	}
	if got := second.calls; len(got) != 1 || got[0] != "dns-off bg0" {
		t.Fatalf("%v", got)
	}

	// and a node that gave it back itself leaves nothing behind
	j = NewJournal(&dnsCfg{}, path)
	_ = j.SetLinkDNS(ctx, "bg0", []netip.Addr{netip.MustParseAddr("10.20.0.1")})
	_ = j.SetLinkDNS(ctx, "bg0", nil)
	third := &dnsCfg{}
	if n := NewJournal(third, path).Recover(ctx); n != 0 {
		t.Fatalf("recovered %d entries although it cleaned up", n)
	}
}

// The record of a removal that failed has to stay: it is the only thing that
// ever gives this host its names back. On 2026-10-22 the journal cleared it
// anyway and deleted itself, the Mac kept sending every name to a resolver
// inside a tunnel that was gone, and nothing short of a reboot helped
// (R144).
func TestAResolverThatCouldNotBeGivenBackKeepsItsRecord(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "netstate.json")
	stuck := &dnsCfg{offErr: errors.New("netcfg: the system configuration did not take the resolver: context deadline exceeded")}
	j := NewJournal(stuck, path)
	if err := j.SetLinkDNS(ctx, "utun12", []netip.Addr{netip.MustParseAddr("10.60.0.53")}); err != nil {
		t.Fatal(err)
	}
	if err := j.SetLinkDNS(ctx, "utun12", nil); err == nil {
		t.Fatal("the failed removal was reported as done")
	}
	if b, err := os.ReadFile(path); err != nil || !strings.Contains(string(b), "utun12") {
		t.Fatalf("the journal forgot the resolver it could not give back: %s %v", b, err)
	}

	// recovery tries again -- three times, and keeps the record while it
	// does not get through
	stuck.offs = 0
	if n := NewJournal(stuck, path).Recover(ctx); n != 1 {
		t.Fatalf("recovered %d entries", n)
	}
	if stuck.offs != 3 {
		t.Errorf("recovery tried %d times, want 3", stuck.offs)
	}
	if b, err := os.ReadFile(path); err != nil || !strings.Contains(string(b), "utun12") {
		t.Fatalf("recovery that did not get through dropped the record: %s %v", b, err)
	}

	// and when it does get through, the record goes with it
	second := &dnsCfg{}
	if n := NewJournal(second, path).Recover(ctx); n != 1 {
		t.Fatalf("recovered %d entries", n)
	}
	if got := second.calls; len(got) != 1 || got[0] != "dns-off utun12" {
		t.Fatalf("%v", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the record stayed although the resolver was given back")
	}
}

// A platform whose daemon cannot do it says so, and LinkDNS does not claim
// it can just because the journal takes the call.
func TestLinkDNSOnAPlatformWithoutIt(t *testing.T) {
	j := NewJournal(&fakeCfg{}, filepath.Join(t.TempDir(), "netstate.json"))
	if _, ok := LinkDNS(j); ok {
		t.Fatal("LinkDNS claims a configurator that cannot do it")
	}
	if err := j.SetLinkDNS(context.Background(), "bg0", []netip.Addr{netip.MustParseAddr("10.20.0.1")}); err == nil {
		t.Fatal("no error from a configurator that cannot set the resolver")
	}
}

// A name taken by something else -- a directory of the worker's where the
// journal would be written (R145) -- does not keep the journal from its
// record: the writer owns the directory and clears the name first. And a
// previous process's journal that is not this user's file is not read, so
// that nobody dictates what root removes.
func TestTheJournalReclaimsItsName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netstate.json")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &fakeCfg{}
	j := NewJournal(f, path)
	if n := j.Recover(context.Background()); n != 0 {
		t.Fatalf("recovered %d entries from a directory", n)
	}
	if err := j.AddBypass(context.Background(), netip.MustParseAddr("203.0.113.7")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("the journal after a record over a squatted name: %v %v", fi, err)
	}
	if !j.HasBypass(netip.MustParseAddr("203.0.113.7")) || j.HasBypass(netip.MustParseAddr("203.0.113.8")) {
		t.Fatal("HasBypass does not answer from the record")
	}
	// the next process recovers from what was written
	g := &fakeCfg{}
	if n := NewJournal(g, path).Recover(context.Background()); n != 1 || strings.Join(g.calls, ";") != "unbypass 203.0.113.7" {
		t.Fatalf("recover: %d %v", n, g.calls)
	}
	// a symbolic link under the name: removed, not followed, on the next write
	if err := os.Symlink("/etc/hostname", path); err != nil {
		t.Fatal(err)
	}
	if err := j.AddBypass(context.Background(), netip.MustParseAddr("203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the journal was written through a link")
	}
}

// hangCfg is a host whose commands never answer: each one runs into its
// deadline, and whether it took effect is unknown.
type hangCfg struct{ fakeCfg }

func (h *hangCfg) AddRoute(ctx context.Context, d netip.Prefix, i string) error {
	<-ctx.Done()
	return ctx.Err()
}
func (h *hangCfg) AddBypass(ctx context.Context, a netip.Addr) error {
	<-ctx.Done()
	return ctx.Err()
}
func (h *hangCfg) SetNAT(ctx context.Context, _ netip.Prefix, d []netip.Prefix, i string) error {
	<-ctx.Done()
	return ctx.Err()
}

// A change whose command never answered may have been made: it is
// recorded, so that a crash does not leave it behind unrecorded. One that
// answered with an error made nothing and is not.
func TestAChangeThatNeverAnsweredIsRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netstate.json")
	j := NewJournal(&hangCfg{}, path)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lan, pool := netip.MustParsePrefix("10.60.0.0/24"), netip.MustParsePrefix("10.21.0.0/16")
	hub := netip.MustParseAddr("203.0.113.7")
	if j.AddRoute(ctx, lan, "utun4") == nil || j.AddBypass(ctx, hub) == nil || j.SetNAT(ctx, pool, []netip.Prefix{lan}, "bg0") == nil {
		t.Fatal("a command cut off is an error to the caller")
	}
	// refused outright: nothing to record
	refused := &failCfg{}
	j2 := NewJournal(refused, filepath.Join(t.TempDir(), "netstate.json"))
	if j2.AddRoute(context.Background(), lan, "utun5") == nil {
		t.Fatal("the refusal must reach the caller")
	}
	if _, err := os.Stat(j2.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused change was recorded")
	}

	next := &fakeCfg{}
	if n := NewJournal(next, path).Recover(context.Background()); n != 3 {
		t.Fatalf("recovered %d, want the route, the host route and the NAT: %v", n, next.calls)
	}
	want := []string{"del 10.60.0.0/24 utun4", "unbypass 203.0.113.7", "nat-off bg0"}
	if !reflect.DeepEqual(next.calls, want) {
		t.Fatalf("calls %v, want %v", next.calls, want)
	}
}

type failCfg struct{ fakeCfg }

func (f *failCfg) AddRoute(context.Context, netip.Prefix, string) error {
	return errors.New("no such device")
}
