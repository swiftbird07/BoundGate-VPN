package registry

import (
	"net/netip"
	"testing"
)

func TestParseAddrEntryCanonicalForm(t *testing.T) {
	for in, want := range map[string]string{
		"10.60.0.10":               "10.60.0.10",
		" 10.60.0.10 ":             "10.60.0.10",
		"10.60.0.10/32":            "10.60.0.10",
		"10.60.0.5/24":             "10.60.0.0/24",
		"10.60.0.10:443":           "10.60.0.10:443",
		"10.60.0.0/24:8000-8100":   "10.60.0.0/24:8000-8100",
		"10.60.0.1-10.60.0.3":      "10.60.0.1-10.60.0.3",
		"10.60.0.0-10.60.0.255":    "10.60.0.0/24",
		"10.60.0.1-10.60.0.3:53":   "10.60.0.1-10.60.0.3:53",
		"2001:db8::1":              "2001:db8::1",
		"2001:db8::/32":            "2001:db8::/32",
		"[2001:db8::1]:443":        "[2001:db8::1]:443",
		"[2001:db8::/32]:443-1000": "[2001:db8::/32]:443-1000",
	} {
		e, ok, err := ParseAddrEntry(in)
		if err != nil || !ok {
			t.Fatalf("%q: ok=%v err=%v", in, ok, err)
		}
		if e.String() != want {
			t.Fatalf("%q became %q, want %q", in, e.String(), want)
		}
	}
}

func TestParseAddrEntryNamesAndMistakes(t *testing.T) {
	for _, name := range []string{"api.github.com", "*.github.com", "myip.wtf"} {
		if _, ok, err := ParseAddrEntry(name); ok || err != nil {
			t.Fatalf("%q is a name: ok=%v err=%v", name, ok, err)
		}
	}
	for _, bad := range []string{"api.github.com:443", "10.60.0.10:0", "10.60.0.10:99999", "10.60.0.10:443-1", "[2001:db8::1", "[2001:db8::1]x", "10.60.0.10:https"} {
		if _, _, err := ParseAddrEntry(bad); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
	// a range whose ends are the wrong way round or of different families
	for _, bad := range []string{"10.60.0.9-10.60.0.1", "10.60.0.1-2001:db8::1"} {
		if _, ok, _ := ParseAddrEntry(bad); ok {
			t.Fatalf("%q was read as a range", bad)
		}
	}
}

func TestAddrEntryMatches(t *testing.T) {
	e, _, err := ParseAddrEntry("10.60.0.0/24:443")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ip    string
		port  uint16
		match bool
	}{
		{"10.60.0.1", 443, true},
		{"10.60.0.255", 443, true},
		{"10.60.1.0", 443, false},
		{"10.60.0.1", 80, false},
		{"2001:db8::1", 443, false},
	} {
		if got := e.Matches(netip.MustParseAddr(c.ip), c.port); got != c.match {
			t.Fatalf("%s:%d matched=%v, want %v", c.ip, c.port, got, c.match)
		}
	}
	any, _, _ := ParseAddrEntry("10.60.0.10")
	if !any.Matches(netip.MustParseAddr("10.60.0.10"), 12345) || any.Matches(netip.MustParseAddr("10.60.0.11"), 80) {
		t.Fatal("an entry without a port matches every port of its address, and no other address")
	}
}
