package netcfg

import (
	"net/netip"
	"testing"
)

// Windows decides in the name resolution policy table, and a rule there
// outlives the process *and* a reboot -- so the rule's name has to be
// recognisable as ours and tied to one device, or a repair cannot find it
// again (R144). These are the pieces of that, checkable on any platform.
func TestTheWindowsPolicyRuleNamesOneDevice(t *testing.T) {
	got, err := winNRPTRule("BoundGate")
	if err != nil || got != "BoundGate-BoundGate" {
		t.Fatalf("%q %v", got, err)
	}
	if iface := winNRPTIface(got); iface != "BoundGate" {
		t.Errorf("the device was lost: %q", iface)
	}
	for _, name := range []string{"", `a\b`, "a/b", "a b", "a\tb", "a\"b"} {
		if _, err := winNRPTRule(name); err == nil {
			t.Errorf("%q was accepted as a device name", name)
		}
	}
	for _, rule := range []string{"SomeoneElse", "BoundGate-", `BoundGate-a\b`, "BoundGate-a/b"} {
		if iface := winNRPTIface(rule); iface != "" {
			t.Errorf("%q was taken for ours (%q)", rule, iface)
		}
	}
	if got := winNRPTServers([]netip.Addr{
		netip.MustParseAddr("10.20.0.1"),
		netip.MustParseAddr("::ffff:10.20.0.2"),
		netip.MustParseAddr("2001:db8::53"),
	}); got != "10.20.0.1;10.20.0.2;2001:db8::53" {
		t.Errorf("servers: %q", got)
	}
}
