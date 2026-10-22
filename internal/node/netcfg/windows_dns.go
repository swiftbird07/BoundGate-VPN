package netcfg

import (
	"fmt"
	"net/netip"
	"strings"
)

// Windows decides in the Name Resolution Policy Table which resolver a name
// goes to. A node with `resolver: hub` needs *every* name to go through the
// tunnel, so that the hub sees the query and a dynamic access list can match
// what the answer named (docs/ACL.md) -- and the adapter's own resolvers
// (SetInterfaceDnsSettings, winipcfg's SetDNS) are not enough on their own:
// Windows asks the resolvers of the other adapters in parallel ("smart
// multi-homed name resolution") and takes whichever answers first, which is
// the leak this is about. A rule for "." is what settles it.
//
// Unlike the macOS entry, such a rule lives in the registry and survives a
// reboot. So the node writes it down in its journal, and
// `boundgate-node -repair` sweeps these keys: a daemon killed between
// writing the rule and writing its record must not leave a Windows machine
// resolving into a tunnel that is gone (R144).
const winNRPTPath = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`

// winNRPTRule names the rule of one tunnel device, recognisable as ours so a
// sweep finds it again. The device name comes from the system; anything that
// could leave the key it belongs in is refused rather than written.
func winNRPTRule(ifname string) (string, error) {
	if ifname == "" || strings.ContainsAny(ifname, "\\/ \t\r\n\"") {
		return "", fmt.Errorf("netcfg: %q is not a device name", ifname)
	}
	return "BoundGate-" + ifname, nil
}

// winNRPTIface is the device a rule was written for, or "" when the key is
// not one of ours.
func winNRPTIface(rule string) string {
	name, ok := strings.CutPrefix(rule, "BoundGate-")
	if !ok || name == "" || strings.ContainsAny(name, "\\/") {
		return ""
	}
	return name
}

// winNRPTServers is how the rule stores the resolvers: one string, separated
// by semicolons.
func winNRPTServers(servers []netip.Addr) string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		out = append(out, s.Unmap().String())
	}
	return strings.Join(out, ";")
}
