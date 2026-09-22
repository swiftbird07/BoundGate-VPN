//go:build linux

package netcfg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

type linuxCfg struct {
	own *ownIfaces
	// arrival: routes through the tunnel go into arrivalTable
	// (ReplyViaArrival) instead of the main table
	arrival *atomic.Bool
}

// New returns the Linux configurator. It shells out to iproute2 and
// nftables; that keeps the prototype small and the commands auditable.
func New() Configurator { return linuxCfg{own: &ownIfaces{}, arrival: &atomic.Bool{}} }

const nftTable = "boundgate"

func (c linuxCfg) CreateTUN(name string, mtu int) (tun.Device, string, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, "", fmt.Errorf("netcfg: create tun %s: %w", name, err)
	}
	n, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, "", err
	}
	c.own.add(n)
	return dev, n, nil
}

func (linuxCfg) SetAddress(ctx context.Context, ifname string, addr netip.Prefix, mtu int) error {
	if err := run(ctx, "ip", "addr", "replace", addr.String(), "dev", ifname); err != nil {
		return err
	}
	return run(ctx, "ip", "link", "set", "dev", ifname, "up", "mtu", strconv.Itoa(mtu))
}

func (c linuxCfg) AddRoute(ctx context.Context, dst netip.Prefix, ifname string) error {
	return run(ctx, append([]string{"ip", "route", "replace", dst.String(), "dev", ifname}, c.table()...)...)
}

func (c linuxCfg) DelRoute(ctx context.Context, dst netip.Prefix, ifname string) error {
	return run(ctx, append([]string{"ip", "route", "del", dst.String(), "dev", ifname}, c.table()...)...)
}

func (c linuxCfg) table() []string {
	if c.arrival != nil && c.arrival.Load() {
		return []string{"table", strconv.Itoa(arrivalTable)}
	}
	return nil
}

// Reply via arrival (ArrivalRouter). The tunnel's routes live in their own
// table, consulted after the main table without its default route:
//
//	5180  fwmark 0x4000/0x4000 lookup main           replies of connections from outside
//	5181  lookup main suppress_prefixlength 0        the LAN, host routes to hubs and control plane
//	5182  lookup 5184                                the tunnel: 0/1, 128/1, the overlay, ...
//
// A connection that comes in from outside to this host (not through the
// tunnel, to one of its own addresses; ports Docker publishes too, the mark
// comes before Docker's DNAT) gets the connection mark, and every packet of
// it carries it as its packet mark, forwarded ones from containers too. So
// its replies take the main table and leave through the gateway they came
// from. What this host and its containers start themselves has no mark and
// goes through the tunnel, where the hub's policies decide.
const (
	arrivalTable = 5184
	arrivalMark  = "0x4000"
	arrivalNft   = "boundgate_arrival"
)

// ArrivalRules renders the nftables script ReplyViaArrival installs.
func ArrivalRules(ifname string) string {
	return fmt.Sprintf(`table inet %[1]s {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    ct state new iifname != %[2]q fib daddr type local ct mark set ct mark | %[3]s
    ct mark & %[3]s == %[3]s meta mark set meta mark | %[3]s
  }
  chain output {
    type route hook output priority mangle; policy accept;
    ct mark & %[3]s == %[3]s meta mark set meta mark | %[3]s
  }
}
`, arrivalNft, ifname, arrivalMark)
}

// arrivalRuleArgs are the `ip rule add` arguments, per family (-4, -6).
func arrivalRuleArgs() [][]string {
	return [][]string{
		{"pref", "5180", "fwmark", arrivalMark + "/" + arrivalMark, "lookup", "main"},
		{"pref", "5181", "lookup", "main", "suppress_prefixlength", "0"},
		{"pref", "5182", "lookup", strconv.Itoa(arrivalTable)},
	}
}

func (c linuxCfg) ReplyViaArrival(ctx context.Context, ifname string, on bool) error {
	// always from a clean state: an earlier process may have left some of it
	for _, fam := range []string{"-4", "-6"} {
		for _, r := range arrivalRuleArgs() {
			for run(ctx, "ip", fam, "rule", "del", r[0], r[1]) == nil {
			}
		}
		_ = run(ctx, "ip", fam, "route", "flush", "table", strconv.Itoa(arrivalTable))
	}
	_ = run(ctx, "nft", "delete", "table", "inet", arrivalNft)
	c.arrival.Store(false)
	if !on {
		return nil
	}
	if err := runStdin(ctx, ArrivalRules(ifname), "nft", "-f", "-"); err != nil {
		return err
	}
	for _, fam := range []string{"-4", "-6"} {
		for _, r := range arrivalRuleArgs() {
			if err := run(ctx, append([]string{"ip", fam, "rule", "add"}, r...)...); err != nil {
				if fam == "-6" {
					break // a host without IPv6: the tunnel carries IPv4 only anyway
				}
				_ = c.ReplyViaArrival(ctx, ifname, false)
				return err
			}
		}
	}
	c.arrival.Store(true)
	return nil
}

type routeGet struct {
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	Metric  int    `json:"metric"`
}

func (c linuxCfg) AddBypass(ctx context.Context, host netip.Addr) error {
	out, err := exec.CommandContext(ctx, "ip", "-j", "route", "get", host.String()).Output()
	if err != nil {
		return fmt.Errorf("netcfg: route lookup for %s: %w", host, err)
	}
	var rs []routeGet
	if err := json.Unmarshal(out, &rs); err != nil || len(rs) == 0 {
		return fmt.Errorf("netcfg: parse route for %s: %v", host, err)
	}
	r := rs[0]
	// Under a full-tunnel profile the node's own device answers for every
	// address, also for a hub whose host route is being renewed after a
	// network change: the way out is then the default route, which the
	// profile's /1 halves leave in place.
	if c.own.has(r.Dev) {
		fam := "-4"
		if host.Is6() {
			fam = "-6"
		}
		out, err := exec.CommandContext(ctx, "ip", "-j", fam, "route", "show", "default").Output()
		if err != nil {
			return fmt.Errorf("netcfg: default route lookup for %s: %w", host, err)
		}
		if r, err = linuxDefaultRoute(out, c.own.has); err != nil {
			return fmt.Errorf("netcfg: %s: %w", host, err)
		}
	}
	args := []string{"ip", "route", "replace", host.String() + "/" + strconv.Itoa(host.BitLen()), "dev", r.Dev}
	if r.Gateway != "" {
		args = append(args, "via", r.Gateway)
	}
	return run(ctx, args...)
}

// linuxDefaultRoute picks the default route with the lowest metric from
// `ip -j route show default`, leaving out the node's own devices.
func linuxDefaultRoute(out []byte, own func(string) bool) (routeGet, error) {
	var rs []routeGet
	if err := json.Unmarshal(out, &rs); err != nil {
		return routeGet{}, fmt.Errorf("parse default routes: %w", err)
	}
	best, found := routeGet{}, false
	for _, r := range rs {
		if r.Dev == "" || own(r.Dev) || (found && r.Metric >= best.Metric) {
			continue
		}
		best, found = r, true
	}
	if !found {
		return routeGet{}, errors.New("no default route outside the tunnel")
	}
	return best, nil
}

func (linuxCfg) DelBypass(ctx context.Context, host netip.Addr) error {
	return run(ctx, "ip", "route", "del", host.String()+"/"+strconv.Itoa(host.BitLen()))
}

func (linuxCfg) EnableForwarding(context.Context) error {
	const p = "/proc/sys/net/ipv4/ip_forward"
	cur, err := os.ReadFile(p)
	if err == nil && strings.TrimSpace(string(cur)) == "1" {
		return nil
	}
	if err := os.WriteFile(p, []byte("1\n"), 0); err != nil {
		return fmt.Errorf("netcfg: enable ip_forward (set sysctl net.ipv4.ip_forward=1 on the host or container): %w", err)
	}
	return nil
}

// AllowForward: on a Docker host the filter table's FORWARD chain drops by
// policy, and a node that shares the host's network (network_mode: host, or
// no container at all) would forward nothing: every packet from the TUN to
// the LAN or the internet ends there, whatever this node's own rules say (a
// drop in one chain is final). Docker leaves the chain DOCKER-USER to the
// host's administrator for exactly this; the node puts two rules there:
//
//	iifname "bg0" counter accept
//	oifname "bg0" counter accept
//
// What leaves the TUN has passed the node's ACL; what enters it is checked
// by the node before it goes into a tunnel. Written with nft in the form
// iptables-nft writes itself, so `iptables -S` and Docker keep working. With
// iptables-legacy the chain is not visible to nft and nothing is done.
func (linuxCfg) AllowForward(ctx context.Context, ifname string, on bool) (bool, error) {
	out, err := exec.CommandContext(ctx, "nft", "-a", "list", "chain", "ip", "filter", "DOCKER-USER").Output()
	if err != nil {
		return false, nil // no Docker, or not the nf_tables backend
	}
	for _, h := range forwardRuleHandles(string(out), ifname) { // also what a predecessor that crashed left
		_ = run(ctx, "nft", "delete", "rule", "ip", "filter", "DOCKER-USER", "handle", h)
	}
	if !on {
		return true, nil
	}
	for _, dir := range []string{"iifname", "oifname"} {
		if err := run(ctx, "nft", "insert", "rule", "ip", "filter", "DOCKER-USER", dir, ifname, "counter", "accept"); err != nil {
			return true, fmt.Errorf("netcfg: let Docker's FORWARD chain pass %s: %w", ifname, err)
		}
	}
	return true, nil
}

// forwardRuleHandles finds the rules AllowForward wrote for ifname in the
// output of `nft -a list chain`; rules in any other form are somebody else's.
func forwardRuleHandles(listing, ifname string) []string {
	re := regexp.MustCompile(`^\s*[io]ifname "` + regexp.QuoteMeta(ifname) + `" counter packets \d+ bytes \d+ accept # handle (\d+)\s*$`)
	var out []string
	for _, line := range strings.Split(listing, "\n") {
		if m := re.FindStringSubmatch(line); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// SetNAT replaces the boundgate nftables table. Rules are generated, so the
// exact text is reproducible for review:
//
//	table ip boundgate {
//	  chain postrouting { type nat hook postrouting priority srcnat; policy accept;
//	    ip saddr <pool> ip daddr <dst> oifname != "bg0" masquerade   (per dst)
//	  }
//	}
func (linuxCfg) SetNAT(ctx context.Context, pool netip.Prefix, dsts []netip.Prefix, ifname string) error {
	_ = run(ctx, "nft", "delete", "table", "ip", nftTable)
	if len(dsts) == 0 {
		return nil
	}
	return runStdin(ctx, NATRules(pool, dsts, ifname), "nft", "-f", "-")
}

// NATRules renders the nftables script SetNAT installs.
func NATRules(pool netip.Prefix, dsts []netip.Prefix, ifname string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table ip %s {\n  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n", nftTable)
	for _, d := range dsts {
		d = d.Masked()
		if d.Bits() == 0 {
			fmt.Fprintf(&b, "    ip saddr %s oifname != %q masquerade\n", pool.Masked(), ifname)
			continue
		}
		fmt.Fprintf(&b, "    ip saddr %s ip daddr %s oifname != %q masquerade\n", pool.Masked(), d, ifname)
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

func run(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netcfg: %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runStdin(ctx context.Context, stdin string, args ...string) error {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netcfg: %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
