package dnsmap

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func TestNamesAreKeptPerPeerAndExpire(t *testing.T) {
	m := New(100)
	m.Learn("node-a", "api.github.com", addrs("140.82.121.4", "2606:50c0::1"), 30*time.Second, t0)

	one := netip.MustParseAddr("140.82.121.4")
	if got := m.Names("node-a", one, t0); len(got) != 1 || got[0] != "api.github.com" {
		t.Fatalf("names %v", got)
	}
	if got := m.Names("node-b", one, t0); got != nil {
		t.Fatalf("what one device resolved says nothing about another: %v", got)
	}
	if got := m.Names("node-a", netip.MustParseAddr("2606:50c0::1"), t0); len(got) != 1 {
		t.Fatalf("the answer's IPv6 address counts too: %v", got)
	}

	// 30 s becomes MinTTL + Grace: still there after five minutes, gone
	// after seven
	if got := m.Names("node-a", one, t0.Add(5*time.Minute)); len(got) != 1 {
		t.Fatalf("a short time to live is stretched to %s + %s: %v", MinTTL, Grace, got)
	}
	if got := m.Names("node-a", one, t0.Add(7*time.Minute)); got != nil {
		t.Fatalf("still there long after: %v", got)
	}
	m.Expire(t0.Add(7 * time.Minute))
	if m.Len() != 0 {
		t.Fatalf("expired entries stay in the map: %d", m.Len())
	}
}

func TestSecondNameForTheSameAddressAndTheLimits(t *testing.T) {
	m := New(2)
	one := netip.MustParseAddr("10.60.0.10")
	m.Learn("node-a", "a.example", addrs("10.60.0.10"), time.Hour, t0)
	m.Learn("node-a", "b.example", addrs("10.60.0.10"), time.Hour, t0)
	if got := m.Names("node-a", one, t0); len(got) != 2 {
		t.Fatalf("a shared address keeps both names: %v", got)
	}
	// MaxTTL caps what an answer may claim
	if got := m.Names("node-a", one, t0.Add(MaxTTL+Grace+time.Second)); got != nil {
		t.Fatalf("a time to live of a year: %v", got)
	}

	m = New(2)
	m.Learn("node-a", "a.example", addrs("10.60.0.10", "10.60.0.11", "10.60.0.12"), time.Hour, t0)
	if m.Len() != 2 || m.Dropped() != 1 {
		t.Fatalf("the map is bounded: %d entries, %d dropped", m.Len(), m.Dropped())
	}
	// once the entries expire the space is free again
	m.Learn("node-a", "b.example", addrs("10.60.0.20"), time.Hour, t0.Add(2*time.Hour))
	if got := m.Names("node-a", netip.MustParseAddr("10.60.0.20"), t0.Add(2*time.Hour)); len(got) != 1 {
		t.Fatalf("expired entries make room: %v", got)
	}
}

func TestManyNamesForOneAddressAreBounded(t *testing.T) {
	m := New(10)
	one := netip.MustParseAddr("10.60.0.10")
	for i := range MaxNames + 4 {
		m.Learn("node-a", strings.Repeat("x", i+1)+".example", addrs("10.60.0.10"), time.Hour, t0)
	}
	if got := m.Names("node-a", one, t0); len(got) != MaxNames {
		t.Fatalf("%d names for one address", len(got))
	}
}
