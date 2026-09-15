//go:build linux

package netcfg

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

type linuxCfg struct{}

// New returns the Linux configurator. It shells out to iproute2 and
// nftables; that keeps the prototype small and the commands auditable.
func New() Configurator { return linuxCfg{} }

const nftTable = "boundgate"

func (linuxCfg) CreateTUN(name string, mtu int) (tun.Device, string, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, "", fmt.Errorf("netcfg: create tun %s: %w", name, err)
	}
	n, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, "", err
	}
	return dev, n, nil
}

func (linuxCfg) SetAddress(ctx context.Context, ifname string, addr netip.Prefix, mtu int) error {
	if err := run(ctx, "ip", "addr", "replace", addr.String(), "dev", ifname); err != nil {
		return err
	}
	return run(ctx, "ip", "link", "set", "dev", ifname, "up", "mtu", strconv.Itoa(mtu))
}

func (linuxCfg) AddRoute(ctx context.Context, dst netip.Prefix, ifname string) error {
	return run(ctx, "ip", "route", "replace", dst.String(), "dev", ifname)
}

func (linuxCfg) DelRoute(ctx context.Context, dst netip.Prefix, ifname string) error {
	return run(ctx, "ip", "route", "del", dst.String(), "dev", ifname)
}

type routeGet struct {
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
}

func (linuxCfg) AddBypass(ctx context.Context, host netip.Addr) error {
	out, err := exec.CommandContext(ctx, "ip", "-j", "route", "get", host.String()).Output()
	if err != nil {
		return fmt.Errorf("netcfg: route lookup for %s: %w", host, err)
	}
	var rs []routeGet
	if err := json.Unmarshal(out, &rs); err != nil || len(rs) == 0 {
		return fmt.Errorf("netcfg: parse route for %s: %v", host, err)
	}
	r := rs[0]
	args := []string{"ip", "route", "replace", host.String() + "/" + strconv.Itoa(host.BitLen()), "dev", r.Dev}
	if r.Gateway != "" {
		args = append(args, "via", r.Gateway)
	}
	return run(ctx, args...)
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
