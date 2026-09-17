package netcfg

import (
	"bufio"
	"fmt"
	"net/netip"
	"strings"
)

// The macOS configurator shells out to ifconfig(8) and route(8). Building
// and parsing their text lives here without a build tag so the tests run on
// every platform.

// darwinTUNName maps a configured device name to what the utun driver
// accepts: "utun" (next free unit) or "utunN".
func darwinTUNName(name string) string {
	if strings.HasPrefix(name, "utun") {
		return name
	}
	return "utun"
}

// darwinAddrArgs: utun is point-to-point; the overlay address is both ends
// and the pool route is added separately.
func darwinAddrArgs(ifname string, addr netip.Prefix, mtu int) []string {
	a := addr.Addr().String()
	if addr.Addr().Is6() {
		return []string{"ifconfig", ifname, "inet6", a, "prefixlen", "128", "mtu", fmt.Sprint(mtu), "up"}
	}
	return []string{"ifconfig", ifname, "inet", a, a, "netmask", "255.255.255.255", "mtu", fmt.Sprint(mtu), "up"}
}

func darwinFamily(a netip.Addr) string {
	if a.Is6() {
		return "-inet6"
	}
	return "-inet"
}

// darwinRouteArgs builds route(8) arguments: verb is add, change or delete.
func darwinRouteArgs(verb string, dst netip.Prefix, ifname string) []string {
	dst = dst.Masked()
	return []string{"route", "-n", verb, darwinFamily(dst.Addr()), "-net", dst.String(), "-interface", ifname}
}

// darwinRoute is what `route -n get` says about a destination.
type darwinRoute struct {
	Gateway string
	Iface   string
}

func parseDarwinRouteGet(out string) (darwinRoute, error) {
	var r darwinRoute
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "gateway":
			r.Gateway = strings.TrimSpace(v)
		case "interface":
			r.Iface = strings.TrimSpace(v)
		}
	}
	if r.Iface == "" {
		return r, fmt.Errorf("netcfg: no interface in route output")
	}
	return r, nil
}

// darwinBypassArgs pins host via the path `route get` reported. A gateway
// that is not an IP address (a link-layer "link#N" or an interface name on
// directly connected networks) means: on-link, route by interface.
func darwinBypassArgs(verb string, host netip.Addr, r darwinRoute) []string {
	args := []string{"route", "-n", verb, darwinFamily(host), "-host", host.String()}
	if verb == "delete" {
		return args
	}
	if gw, err := netip.ParseAddr(r.Gateway); err == nil && !gw.IsLoopback() {
		return append(args, gw.String())
	}
	return append(args, "-interface", r.Iface)
}
