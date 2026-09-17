package node

import (
	"fmt"
	"net"
	"net/netip"
)

// Overlap guard (R25). Routing a prefix through the tunnel is harmful when
// this machine already lives in it:
//
//   - a local network that contains the prefix (the home LAN is
//     192.168.178.0/24 and a subnet router announces 192.168.178.0/24): the
//     tunnel route would cut the machine off from its own LAN;
//   - a point-to-point address inside the prefix (another VPN's tunnel
//     address 10.21.0.9 and an overlay pool 10.21.0.0/16): the tunnel route
//     is more specific than that VPN's routes and takes its traffic.
//
// A broad tunnel prefix around a narrower local network (10.0.0.0/8 while on
// a 10.0.0.0/24 Wi-Fi) is fine: the on-link route stays more specific.
// Shadowed default routes (/0, /1) are never a conflict.
type localNet struct {
	Iface  string
	Prefix netip.Prefix // address with its mask, not masked
}

func conflictWith(p netip.Prefix, locals []localNet) (localNet, bool) {
	p = p.Masked()
	if p.Bits() <= 1 {
		return localNet{}, false
	}
	for _, l := range locals {
		addr := l.Prefix.Addr()
		if addr.Is4() != p.Addr().Is4() {
			continue
		}
		network := l.Prefix.Masked()
		hostRoute := l.Prefix.Bits() == addr.BitLen()
		if hostRoute && p.Contains(addr) {
			return l, true
		}
		if !hostRoute && network.Bits() <= p.Bits() && network.Contains(p.Addr()) {
			return l, true
		}
	}
	return localNet{}, false
}

// localNets lists the addresses of every interface that is up, except
// loopback and the node's own tunnel device.
func localNets(skipIface string) []localNet {
	var out []localNet
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, i := range ifs {
		if i.Name == skipIface || i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok || addr.IsLinkLocalUnicast() {
				continue
			}
			ones, _ := ipn.Mask.Size()
			out = append(out, localNet{Iface: i.Name, Prefix: netip.PrefixFrom(addr.Unmap(), ones)})
		}
	}
	return out
}

func describeConflict(p netip.Prefix, l localNet) string {
	return fmt.Sprintf("%s overlaps %s on %s", p, l.Prefix, l.Iface)
}
