//go:build linux

package netcfg

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

// fakeBus records what would have gone to systemd-resolved.
type fakeBus struct {
	calls []busMsg
	err   error
	open  bool
}

type busMsg struct {
	method string
	args   []any
}

func (b *fakeBus) call(_ context.Context, method string, args ...any) error {
	b.calls = append(b.calls, busMsg{method, args})
	return b.err
}

func (b *fakeBus) Close() error { b.open = false; return nil }

func TestSetLinkDNSTellsResolvedTheServersAndSendsEveryNameThere(t *testing.T) {
	bus := &fakeBus{}
	err := setLinkDNS(context.Background(), bus, 7, []netip.Addr{
		netip.MustParseAddr("10.20.0.1"),
		netip.MustParseAddr("::ffff:10.20.0.2"), // a v4 address in v6 clothing
		netip.MustParseAddr("2001:db8::53"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bus.calls) != 2 {
		t.Fatalf("%d calls: %+v", len(bus.calls), bus.calls)
	}
	if bus.calls[0].method != "org.freedesktop.resolve1.Manager.SetLinkDNS" {
		t.Fatalf("method %q", bus.calls[0].method)
	}
	if idx, ok := bus.calls[0].args[0].(int32); !ok || idx != 7 {
		t.Fatalf("link index %v", bus.calls[0].args[0])
	}
	want := []resolvedAddr{
		{Family: afINET, Address: []byte{10, 20, 0, 1}},
		{Family: afINET, Address: []byte{10, 20, 0, 2}},
		{Family: afINET6, Address: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53}},
	}
	if got, ok := bus.calls[0].args[1].([]resolvedAddr); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("addresses %+v, want %+v", bus.calls[0].args[1], want)
	}

	// "~.": every name is asked on this link, so the resolver of the
	// network the machine sits in is not asked behind the node's back
	if bus.calls[1].method != "org.freedesktop.resolve1.Manager.SetLinkDomains" {
		t.Fatalf("method %q", bus.calls[1].method)
	}
	wantDom := []resolvedDomain{{Domain: ".", RoutingOnly: true}}
	if got, ok := bus.calls[1].args[1].([]resolvedDomain); !ok || !reflect.DeepEqual(got, wantDom) {
		t.Fatalf("domains %+v, want %+v", bus.calls[1].args[1], wantDom)
	}
}

func TestSetLinkDNSGivesTheLinkBack(t *testing.T) {
	bus := &fakeBus{}
	if err := setLinkDNS(context.Background(), bus, 3, nil); err != nil {
		t.Fatal(err)
	}
	if len(bus.calls) != 1 || bus.calls[0].method != "org.freedesktop.resolve1.Manager.RevertLink" {
		t.Fatalf("%+v", bus.calls)
	}
	if idx, ok := bus.calls[0].args[0].(int32); !ok || idx != 3 {
		t.Fatalf("link index %v", bus.calls[0].args[0])
	}
}

func TestSetLinkDNSSaysWhatWentWrong(t *testing.T) {
	bus := &fakeBus{err: errors.New("Service org.freedesktop.resolve1 not provided")}
	err := setLinkDNS(context.Background(), bus, 1, []netip.Addr{netip.MustParseAddr("10.20.0.1")})
	if err == nil {
		t.Fatal("no error")
	}
	// the message has to name the host's side of it, not just the method
	if got := err.Error(); !contains(got, "systemd-resolved") {
		t.Fatalf("error %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
