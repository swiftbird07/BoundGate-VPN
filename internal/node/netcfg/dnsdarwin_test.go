package netcfg

import (
	"net/netip"
	"strings"
	"testing"
)

// The scutil script is the whole macOS resolver change, so it is checked to
// the letter: the empty match domain is what makes mDNSResponder ask these
// resolvers for every name (measured 2026-10-22; without it the dictionary
// is ignored), and the key is named after the tunnel device, so a teardown
// removes exactly what this session wrote.
func TestTheMacScriptSendsEveryNameToTheHubsResolvers(t *testing.T) {
	got, err := darwinDNSScript("utun7", []netip.Addr{
		netip.MustParseAddr("10.20.0.1"),
		netip.MustParseAddr("::ffff:10.20.0.2"), // a v4 address in v6 clothing
		netip.MustParseAddr("2001:db8::53"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "d.init\n" +
		"d.add ServerAddresses * 10.20.0.1 10.20.0.2 2001:db8::53\n" +
		"d.add SupplementalMatchDomains * \"\"\n" +
		"set State:/Network/Service/boundgate-utun7/DNS\n" +
		"quit\n"
	if got != want {
		t.Fatalf("script:\n%s\nwant:\n%s", got, want)
	}
	// no search domain: a routing domain only, as on Linux -- nothing is
	// appended to a name the user typed
	if strings.Contains(got, "SearchDomains") {
		t.Error("the script adds a search domain")
	}
}

func TestTheMacScriptGivesTheResolverBack(t *testing.T) {
	got, err := darwinDNSScript("utun7", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "remove State:/Network/Service/boundgate-utun7/DNS\nquit\n" {
		t.Fatalf("script: %q", got)
	}
}

// The device name becomes part of a store key. It comes from the system
// (utunN), so anything else is a bug and is refused rather than written.
func TestTheMacScriptRefusesAStrangeDeviceName(t *testing.T) {
	for _, name := range []string{"", "utun7 ", "utun7/../en0", "u\ntun", "State:/x"} {
		if _, err := darwinDNSScript(name, []netip.Addr{netip.MustParseAddr("10.20.0.1")}); err == nil {
			t.Errorf("%q was accepted", name)
		}
	}
}
