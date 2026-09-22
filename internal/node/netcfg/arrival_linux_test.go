//go:build linux

package netcfg

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestArrivalRules(t *testing.T) {
	got := ArrivalRules("bg0")
	for _, w := range []string{
		`table inet boundgate_arrival`,
		`ct state new iifname != "bg0" fib daddr type local ct mark set ct mark | 0x4000`,
		`type route hook output priority mangle`,
	} {
		if !strings.Contains(got, w) {
			t.Fatalf("rules lack %q:\n%s", w, got)
		}
	}
}

// TestReplyViaArrivalKernel is the NAS behind a router's port forward, with
// a real kernel (make test-arrival: a privileged container, it rewires the
// container's own network):
//
//	inet netns  203.0.113.5 (an internet client), 10.99.0.2 (the router)
//	    | veth
//	this netns  10.99.0.1, default via 10.99.0.2; tun bgt0 with 0/1 and 128/1
//	            (the exit node's routes; nobody reads the tun: what goes in is lost)
//	    | veth, DNAT :18081 -> 172.18.0.2:18080 (a published Docker port)
//	ctr netns   172.18.0.2 (a container)
//
// The client connects to a service here and to the container. Without reply_via_arrival the
// answer goes into the tunnel and the connection fails; with it the answer
// leaves the way it came. What this host starts itself still goes into the
// tunnel.
func TestReplyViaArrivalKernel(t *testing.T) {
	if os.Getenv("BOUNDGATE_TEST_ARRIVAL") == "" {
		t.Skip("needs a privileged container of its own: make test-arrival")
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
	sh("ip", "netns", "add", "inet")
	sh("ip", "link", "add", "veth-a", "type", "veth", "peer", "name", "veth-b")
	sh("ip", "link", "set", "veth-b", "netns", "inet")
	sh("ip", "addr", "add", "10.99.0.1/24", "dev", "veth-a")
	sh("ip", "link", "set", "veth-a", "up")
	sh("ip", "netns", "exec", "inet", "ip", "addr", "add", "10.99.0.2/24", "dev", "veth-b")
	sh("ip", "netns", "exec", "inet", "ip", "addr", "add", "203.0.113.5/32", "dev", "lo")
	sh("ip", "netns", "exec", "inet", "ip", "link", "set", "veth-b", "up")
	sh("ip", "netns", "exec", "inet", "ip", "link", "set", "lo", "up")
	sh("ip", "route", "replace", "default", "via", "10.99.0.2", "dev", "veth-a")
	// a container behind a published port, as Docker does it: bridge + DNAT
	sh("ip", "netns", "add", "ctr")
	sh("ip", "link", "add", "veth-c", "type", "veth", "peer", "name", "veth-d")
	sh("ip", "link", "set", "veth-d", "netns", "ctr")
	sh("ip", "addr", "add", "172.18.0.1/24", "dev", "veth-c")
	sh("ip", "link", "set", "veth-c", "up")
	sh("ip", "netns", "exec", "ctr", "ip", "addr", "add", "172.18.0.2/24", "dev", "veth-d")
	sh("ip", "netns", "exec", "ctr", "ip", "link", "set", "veth-d", "up")
	sh("ip", "netns", "exec", "ctr", "ip", "link", "set", "lo", "up")
	sh("ip", "netns", "exec", "ctr", "ip", "route", "add", "default", "via", "172.18.0.1")
	sh("sysctl", "-qw", "net.ipv4.ip_forward=1")
	sh("nft", "add table ip testnat; add chain ip testnat pre { type nat hook prerouting priority dstnat; }; add rule ip testnat pre tcp dport 18081 dnat to 172.18.0.2:18080")
	srv := exec.Command("ip", "netns", "exec", "ctr", "sh", "-c", "while true; do echo hello from the container | nc -N -l 18080; done")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Process.Kill() }()

	c := New().(linuxCfg)
	dev, ifname, err := c.CreateTUN("bgt0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if err := c.SetAddress(ctx, ifname, netip.MustParsePrefix("10.25.0.9/32"), 1280); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "10.99.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("hello from the nas\n"))
			_ = conn.Close()
		}
	}()
	// the client, from 203.0.113.5 in the other namespace (netcat-openbsd)
	dial := func(port, want string) bool {
		cmd := exec.Command("ip", "netns", "exec", "inet", "nc", "-N", "-w", "3", "-s", "203.0.113.5", "10.99.0.1", port)
		out, _ := cmd.CombinedOutput()
		return strings.Contains(string(out), want)
	}
	client := func() bool { return dial("18080", "hello from the nas") }
	container := func() bool { return dial("18081", "hello from the container") }
	exits := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	routeVia := func(extra ...string) string {
		return sh(append([]string{"ip", "route", "get", "203.0.113.5"}, extra...)...)
	}

	// 1. the problem: the exit's routes in the main table swallow the answer
	for _, p := range exits {
		if err := c.AddRoute(ctx, p, ifname); err != nil {
			t.Fatal(err)
		}
	}
	if client() || container() {
		t.Fatal("without reply_via_arrival the answers should have gone into the tunnel")
	}
	for _, p := range exits {
		_ = c.DelRoute(ctx, p, ifname)
	}

	// 2. reply_via_arrival: the same routes, now in the tunnel's table
	if err := c.ReplyViaArrival(ctx, ifname, true); err != nil {
		t.Fatal(err)
	}
	for _, p := range exits {
		if err := c.AddRoute(ctx, p, ifname); err != nil {
			t.Fatal(err)
		}
	}
	if !client() {
		t.Fatalf("the client got no answer\nrules:\n%s\nnft:\n%s", sh("ip", "rule"), sh("nft", "list", "table", "inet", arrivalNft))
	}
	if !container() {
		t.Fatal("the published container port got no answer")
	}
	if r := sh("ip", "route", "get", "203.0.113.5", "from", "172.18.0.2", "iif", "veth-c"); !strings.Contains(r, "dev "+ifname) {
		t.Fatalf("what a container starts must go into the tunnel: %s", r)
	}
	if r := routeVia(); !strings.Contains(r, "dev "+ifname) {
		t.Fatalf("what this host starts must go into the tunnel: %s", r)
	}
	if r := routeVia("mark", arrivalMark); !strings.Contains(r, "dev veth-a") {
		t.Fatalf("marked replies must leave through the gateway: %s", r)
	}

	// 3. off again: nothing left behind
	for _, p := range exits {
		if err := c.DelRoute(ctx, p, ifname); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.ReplyViaArrival(ctx, ifname, false); err != nil {
		t.Fatal(err)
	}
	if rules := sh("ip", "rule"); strings.Contains(rules, "518") {
		t.Fatalf("rules left behind:\n%s", rules)
	}
	if out, err := exec.Command("nft", "list", "table", "inet", arrivalNft).CombinedOutput(); err == nil {
		t.Fatalf("nft table left behind:\n%s", out)
	}
}
