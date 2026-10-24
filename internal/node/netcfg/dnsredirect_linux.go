//go:build linux

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
)

// While the overlay is up, a Linux host's names go to the hub's resolver
// because the node sends them there, not because the host was asked to
// (#18). Every DNS query that leaves the host or is forwarded by it -- port
// 53, UDP and TCP, to an address that is not the host's own, not one that
// came in through the tunnel -- is rewritten to the hub's resolver, and those
// that then leave through the tunnel take the overlay address. So the hub
// sees the question, and a dynamic access list can match the name (the hub
// only learns which address a name stands for when it sees the query,
// docs/ACL.md).
//
// Asking systemd-resolved over D-Bus, which is what this did before, reached
// neither a host without resolved nor a node container without the host's
// bus socket -- and that socket is the host's whole system bus, systemd
// included. It missed Docker's containers too: with 127.0.0.53 in
// /etc/resolv.conf, Docker's embedded DNS forwards to the servers resolved
// lists, past the routing domain "~.". Redirecting needs nothing the node
// does not already have (NET_ADMIN on the host's network) and covers all of
// them. resolved still gets the link setting when a bus happens to be there,
// so `resolvectl` shows where names go; it is no longer what makes it so.
//
// IPv6 queries are refused rather than rewritten: the overlay carries IPv4,
// and a resolver that is refused moves on to its next server, which is then
// redirected. DNS over TLS or HTTPS is out of reach, as it was before.
//
//	table inet boundgate_dns_bg0 {
//	  chain output      { type nat hook output priority dstnat; ... jump to_hub }
//	  chain prerouting  { type nat hook prerouting priority dstnat; iifname != "bg0" ... jump to_hub }
//	  chain to_hub      { fib daddr type local return; ip daddr { <hub's> } return; ... dnat ip to <hub's first> }
//	  chain postrouting { type nat hook postrouting priority srcnat; oifname "bg0" ct mark & 0x8000 == 0x8000 masquerade }
//	  chain refuse_output, refuse_forward { ... IPv6 port 53 reject }
//	}
const (
	dnsNftPrefix = "boundgate_dns_"
	// dnsMark marks a redirected query's connection, so only those are
	// masqueraded (the arrival rules use 0x4000)
	dnsMark = "0x8000"
)

var nftIdent = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// dnsTable is the table that redirects DNS for one tunnel device: one per
// device, so a repair can tell whose it is.
func dnsTable(ifname string) (string, error) {
	if !nftIdent.MatchString(ifname) {
		return "", fmt.Errorf("netcfg: the tunnel device %q cannot name an nftables table; use letters, digits and _", ifname)
	}
	return dnsNftPrefix + ifname, nil
}

// DNSRedirectRules renders the table SetLinkDNS installs for ifname.
func DNSRedirectRules(ifname string, servers []netip.Addr) (string, error) {
	table, err := dnsTable(ifname)
	if err != nil {
		return "", err
	}
	var v4 []string
	for _, s := range servers {
		if s = s.Unmap(); s.Is4() {
			v4 = append(v4, s.String())
		}
	}
	if len(v4) == 0 {
		return "", errors.New("netcfg: the hub offers no IPv4 resolver, and the overlay carries IPv4 only")
	}
	return fmt.Sprintf(`table inet %[1]s {
  chain output {
    type nat hook output priority dstnat; policy accept;
    meta l4proto { tcp, udp } th dport 53 jump to_hub
  }
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname != %[2]q meta l4proto { tcp, udp } th dport 53 jump to_hub
  }
  chain to_hub {
    fib daddr type local return
    ip daddr { %[3]s } return
    meta nfproto ipv4 ct mark set ct mark | %[5]s dnat ip to %[4]s
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname %[2]q ct mark & %[5]s == %[5]s masquerade
  }
  chain refuse_output {
    type filter hook output priority filter; policy accept;
    meta nfproto ipv6 meta l4proto { tcp, udp } th dport 53 fib daddr type != local reject
  }
  chain refuse_forward {
    type filter hook forward priority filter; policy accept;
    iifname != %[2]q meta nfproto ipv6 meta l4proto { tcp, udp } th dport 53 reject
  }
}
`, table, ifname, strings.Join(v4, ", "), v4[0], dnsMark), nil
}

// SetLinkDNS implements LinkDNSConfigurator: the redirect, replaced in one
// transaction, and resolved's link setting when there is a bus. An empty
// list removes both.
func (c linuxCfg) SetLinkDNS(ctx context.Context, ifname string, servers []netip.Addr) error {
	table, err := dnsTable(ifname)
	if err != nil {
		return err
	}
	if len(servers) == 0 {
		if err := dropDNSTable(ctx, table); err != nil {
			return err
		}
		// a link setting left behind would point the host at a tunnel that
		// is gone; no bus, or no device any more, means there is none
		err := c.resolvedLinkDNS(ctx, ifname, nil)
		if err != nil && !errors.Is(err, ErrNoResolver) && !errors.Is(err, errNoDevice) {
			return err
		}
		return nil
	}
	rules, err := DNSRedirectRules(ifname, servers)
	if err != nil {
		return err
	}
	// creating the table first makes the delete succeed on a host without
	// it; the whole script is one transaction, so there is no moment
	// without the rules when they are only replaced
	script := fmt.Sprintf("table inet %[1]s\ndelete table inet %[1]s\n", table) + rules
	if err := runStdin(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("netcfg: send the host's names to the hub's resolver: %w", err)
	}
	_ = c.resolvedLinkDNS(ctx, ifname, servers) // where names go is settled already
	return nil
}

// dropDNSTable removes the redirect; a table that is not there is gone.
func dropDNSTable(ctx context.Context, table string) error {
	err := run(ctx, "nft", "delete", "table", "inet", table)
	if err != nil && strings.Contains(err.Error(), "No such file or directory") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: give the host's names back: %w", err)
	}
	return nil
}

// dnsTables lists the redirect tables on this host, by device.
func dnsTables(ctx context.Context) (map[string]string, error) {
	out, err := exec.CommandContext(ctx, "nft", "list", "tables", "inet").CombinedOutput()
	if errors.Is(err, exec.ErrNotFound) {
		return nil, nil // no nftables, so none of ours either
	}
	if err != nil {
		return nil, fmt.Errorf("netcfg: list nftables tables: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return parseDNSTables(string(out)), nil
}

// parseDNSTables reads `nft list tables inet`: table name by device.
func parseDNSTables(listing string) map[string]string {
	tables := map[string]string{}
	for _, line := range strings.Split(listing, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "table" && f[1] == "inet" && strings.HasPrefix(f[2], dnsNftPrefix) {
			if ifname := strings.TrimPrefix(f[2], dnsNftPrefix); ifname != "" {
				tables[ifname] = f[2]
			}
		}
	}
	return tables
}

// SweepDNS implements DNSSweeper: it removes the redirects of devices that
// are gone. A redirect left behind sends every name of this host, and of its
// containers, into a tunnel that is not there: nothing resolves until it is
// removed (R144). One whose device still exists belongs to a node that is
// running and is left alone.
func (linuxCfg) SweepDNS(ctx context.Context) ([]string, error) {
	tables, err := dnsTables(ctx)
	if err != nil {
		return nil, err
	}
	var removed []string
	for ifname, table := range tables {
		if _, err := net.InterfaceByName(ifname); err == nil {
			continue
		}
		if err := dropDNSTable(ctx, table); err != nil {
			return removed, err
		}
		removed = append(removed, "nft table inet "+table)
	}
	return removed, nil
}

// LiveDNSKeys are the redirects whose device still exists.
func (linuxCfg) LiveDNSKeys(ctx context.Context) []string {
	tables, _ := dnsTables(ctx)
	var live []string
	for ifname, table := range tables {
		if _, err := net.InterfaceByName(ifname); err == nil {
			live = append(live, "nft table inet "+table)
		}
	}
	return live
}
