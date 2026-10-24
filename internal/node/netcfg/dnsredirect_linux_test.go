//go:build linux

package netcfg

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDNSRedirectRules(t *testing.T) {
	got, err := DNSRedirectRules("bg0", []netip.Addr{
		netip.MustParseAddr("2001:db8::53"), // the overlay is IPv4: not a target
		netip.MustParseAddr("::ffff:10.20.0.1"),
		netip.MustParseAddr("10.20.0.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{
		`table inet boundgate_dns_bg0`,
		// the host's own queries, and what it forwards -- not what comes
		// out of the tunnel
		"type nat hook output priority dstnat",
		`iifname != "bg0" meta l4proto { tcp, udp } th dport 53 jump to_hub`,
		// the host's own stub and a query that already goes to the hub stay
		"fib daddr type local return",
		"ip daddr { 10.20.0.1, 10.20.0.2 } return",
		"ct mark set ct mark | 0x8000 dnat ip to 10.20.0.1",
		// only what was redirected takes the overlay address
		`oifname "bg0" ct mark & 0x8000 == 0x8000 masquerade`,
		"meta nfproto ipv6 meta l4proto { tcp, udp } th dport 53 fib daddr type != local reject",
	} {
		if !strings.Contains(got, w) {
			t.Fatalf("rules lack %q:\n%s", w, got)
		}
	}
	if strings.Contains(got, "2001:db8::53") {
		t.Fatalf("an IPv6 resolver became a target:\n%s", got)
	}
	if _, err := DNSRedirectRules("bg0", []netip.Addr{netip.MustParseAddr("2001:db8::53")}); err == nil {
		t.Fatal("no IPv4 resolver, yet rules")
	}
	if _, err := DNSRedirectRules(`bg0"; flush ruleset; "`, []netip.Addr{netip.MustParseAddr("10.20.0.1")}); err == nil {
		t.Fatal("a device name that is no nftables name went into the script")
	}
}

func TestParseDNSTables(t *testing.T) {
	got := parseDNSTables("table inet boundgate_arrival\ntable inet boundgate_dns_bg0\ntable inet boundgate_dns_tun_7\ntable inet other\ntable inet boundgate_dns_\n")
	want := map[string]string{"bg0": "boundgate_dns_bg0", "tun_7": "boundgate_dns_tun_7"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v, want %v", got, want)
	}
}

// TestDNSRedirectKernel: a host whose resolver is the router of its LAN,
// with a real kernel (make test-dns-redirect: a privileged container):
//
//	lan netns   192.168.50.1, a resolver that answers target.lab with 192.0.2.66
//	    | veth, the host's default route
//	this netns  10.99.0.1; 127.0.0.1 has a resolver of its own (192.0.2.77);
//	            bgt1 10.25.0.9 plays the tunnel, 10.97.0.53 is routed into it
//	    | veth "bgt1"
//	hub netns   10.97.0.53, the hub's resolver (target.lab is 10.60.0.10); it
//	            knows no way back but to 10.25.0.9, the overlay address
//	    | veth, forwarded by this host
//	ctr netns   172.18.0.2, a container that asks the LAN's resolver
//
// With the redirect the host and the container both get the hub's answer,
// although they asked the LAN; the local resolver is left alone. Without it
// (and after a repair) they get the LAN's.
func TestDNSRedirectKernel(t *testing.T) {
	if os.Getenv("BOUNDGATE_TEST_DNS_REDIRECT") == "" {
		t.Skip("needs a privileged container of its own: make test-dns-redirect")
	}
	ctx := context.Background()
	sh := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v: %s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	ns := func(name string, args ...string) string {
		t.Helper()
		return sh(append([]string{"ip", "netns", "exec", name}, args...)...)
	}
	veth := func(here, there, netns, hereAddr, thereAddr string) {
		t.Helper()
		sh("ip", "netns", "add", netns)
		sh("ip", "link", "add", here, "type", "veth", "peer", "name", there)
		sh("ip", "link", "set", there, "netns", netns)
		if hereAddr != "" {
			sh("ip", "addr", "add", hereAddr, "dev", here)
		}
		sh("ip", "link", "set", here, "up")
		ns(netns, "ip", "addr", "add", thereAddr, "dev", there)
		ns(netns, "ip", "link", "set", there, "up")
		ns(netns, "ip", "link", "set", "lo", "up")
	}
	dnsmasq := func(netns, listen, answer string) {
		t.Helper()
		args := []string{"dnsmasq", "-k", "-C", "/dev/null", "--no-resolv", "--no-hosts", "--bind-interfaces",
			"--listen-address=" + listen, "--address=/target.lab/" + answer}
		if netns != "" {
			args = append([]string{"ip", "netns", "exec", netns}, args...)
		}
		cmd := exec.Command(args[0], args[1:]...)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill() })
	}
	veth("veth-a", "veth-b", "lan", "10.99.0.1/24", "192.168.50.1/24")
	ns("lan", "ip", "addr", "add", "10.99.0.2/24", "dev", "veth-b")
	sh("ip", "route", "replace", "default", "via", "10.99.0.2", "dev", "veth-a")
	ns("lan", "ip", "route", "add", "default", "via", "10.99.0.1")
	veth("bgt1", "veth-h", "hub", "10.25.0.9/32", "10.97.0.53/32")
	sh("ip", "route", "add", "10.97.0.53/32", "dev", "bgt1")
	ns("hub", "ip", "route", "add", "10.25.0.9/32", "dev", "veth-h")
	veth("veth-c", "veth-d", "ctr", "172.18.0.1/24", "172.18.0.2/24")
	ns("ctr", "ip", "route", "add", "default", "via", "172.18.0.1")
	sh("sysctl", "-qw", "net.ipv4.ip_forward=1")
	// a container's queries leave the host masqueraded, as Docker does it
	sh("nft", "add table ip testnat; add chain ip testnat post { type nat hook postrouting priority srcnat; }; add rule ip testnat post ip saddr 172.18.0.0/24 oifname veth-a masquerade")
	dnsmasq("lan", "192.168.50.1", "192.0.2.66")
	dnsmasq("hub", "10.97.0.53", "10.60.0.10")
	dnsmasq("", "127.0.0.1", "192.0.2.77")
	time.Sleep(300 * time.Millisecond)

	lookup := func(netns, server string) string {
		args := []string{"timeout", "4", "nslookup", "-type=a", "target.lab", server}
		if netns != "" {
			args = append([]string{"ip", "netns", "exec", netns}, args...)
		}
		out, _ := exec.Command(args[0], args[1:]...).CombinedOutput()
		for _, a := range []string{"10.60.0.10", "192.0.2.66", "192.0.2.77"} {
			if strings.Contains(string(out), a) {
				return a
			}
		}
		return "no answer: " + strings.TrimSpace(string(out))
	}
	expect := func(what, netns, server, want string) {
		t.Helper()
		if got := lookup(netns, server); got != want {
			t.Fatalf("%s: %s, want %s\nnft:\n%s", what, got, want, sh("nft", "list", "ruleset"))
		}
	}
	expect("the LAN's resolver, before", "", "192.168.50.1", "192.0.2.66")
	if got := boundQuery(t, "veth-a", "192.168.50.1:53"); got != "192.0.2.66" {
		t.Fatalf("a query bound to the LAN's link, before: %s", got)
	}

	c := New().(linuxCfg)
	hub := []netip.Addr{netip.MustParseAddr("10.97.0.53")}
	if err := c.SetLinkDNS(ctx, "bgt1", hub); err != nil {
		t.Fatal(err)
	}
	// twice: replacing the rules is how a hub's new resolvers arrive
	if err := c.SetLinkDNS(ctx, "bgt1", hub); err != nil {
		t.Fatal(err)
	}
	expect("the host asks its LAN", "", "192.168.50.1", "10.60.0.10")
	expect("a container asks the LAN", "ctr", "192.168.50.1", "10.60.0.10")
	expect("the host asks the hub", "", "10.97.0.53", "10.60.0.10")
	expect("the host's own resolver", "", "127.0.0.1", "192.0.2.77")
	// systemd-resolved sends a link's queries out of that link (IP_UNICAST_IF):
	// on Martins-NAS they left through br0 and never reached the tunnel
	if got := boundQuery(t, "veth-a", "192.168.50.1:53"); got != "10.60.0.10" {
		t.Fatalf("a query bound to the LAN's link: %s, want 10.60.0.10", got)
	}
	if live := c.LiveDNSKeys(ctx); !reflect.DeepEqual(live, []string{"nft table inet boundgate_dns_bgt1"}) {
		t.Fatalf("live: %v", live)
	}

	// given back: the LAN answers again, and nothing of ours is left
	if err := c.SetLinkDNS(ctx, "bgt1", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.SetLinkDNS(ctx, "bgt1", nil); err != nil {
		t.Fatalf("giving back twice: %v", err)
	}
	expect("the LAN's resolver, after", "", "192.168.50.1", "192.0.2.66")
	if out, err := exec.Command("nft", "list", "table", "inet", "boundgate_dns_bgt1").CombinedOutput(); err == nil {
		t.Fatalf("table left behind:\n%s", out)
	}

	// a node that died with the redirect in place: the device goes with
	// the process, the table does not, and nothing resolves until a
	// repair removes it
	if err := c.SetLinkDNS(ctx, "bgt1", hub); err != nil {
		t.Fatal(err)
	}
	sh("ip", "link", "del", "bgt1")
	if got := lookup("", "192.168.50.1"); got == "192.0.2.66" {
		t.Fatal("the redirect of a gone device let a query through: the test proves nothing")
	}
	removed, err := c.SweepDNS(ctx)
	if err != nil || !reflect.DeepEqual(removed, []string{"nft table inet boundgate_dns_bgt1"}) {
		t.Fatalf("sweep: %v %v", removed, err)
	}
	expect("the LAN's resolver, after the repair", "", "192.168.50.1", "192.0.2.66")
}

// boundQuery asks server for target.lab's address from a socket bound to
// ifname the way systemd-resolved binds a link's queries (IP_UNICAST_IF).
func boundQuery(t *testing.T, ifname, server string) string {
	t.Helper()
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		t.Fatal(err)
	}
	const ipUnicastIf = 50 // IP_UNICAST_IF, linux/in.h
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			var idx [4]byte // network byte order, as the option wants it
			binary.BigEndian.PutUint32(idx[:], uint32(iface.Index))
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipUnicastIf, int(binary.NativeEndian.Uint32(idx[:])))
		})
		if err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		t.Fatal(err)
	}
	// id 0x4242, recursion desired, one question: target.lab A IN
	q := []byte{0x42, 0x42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, 't', 'a', 'r', 'g', 'e', 't', 3, 'l', 'a', 'b', 0, 0, 1, 0, 1}
	if _, err := pc.WriteTo(q, dst); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		return "no answer: " + err.Error()
	}
	if n < len(q)+16 || binary.BigEndian.Uint16(buf[6:8]) == 0 {
		return "no address in the answer"
	}
	return netip.AddrFrom4([4]byte(buf[n-4 : n])).String() // the one A record, last
}
