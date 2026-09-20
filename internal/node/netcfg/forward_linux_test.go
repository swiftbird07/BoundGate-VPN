package netcfg

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestForwardRuleHandles(t *testing.T) {
	listing := `table ip filter {
	chain DOCKER-USER { # handle 1
		oifname "bg0" counter packets 12 bytes 3456 accept # handle 5
		iifname "bg0" counter packets 0 bytes 0 accept # handle 4
		iifname "bg0" ip saddr 10.0.0.0/8 counter packets 0 bytes 0 accept # handle 9
		iifname "bg01" counter packets 0 bytes 0 accept # handle 7
		iifname "eth1" counter packets 0 bytes 0 drop # handle 8
	}
}`
	if got := strings.Join(forwardRuleHandles(listing, "bg0"), ","); got != "5,4" {
		t.Fatalf("got %q: only the two rules in the node's own form, for its own device", got)
	}
	if got := forwardRuleHandles(listing, "bg.*"); len(got) != 0 {
		t.Fatalf("the device name is not a pattern: %v", got)
	}
}

// Against a real kernel: needs root, nft and iptables (nf_tables), as in
//
//	docker run --rm --cap-add NET_ADMIN -v $PWD/bin:/b alpine sh -c 'apk add nftables iptables && /b/netcfg.test -test.run AllowForward -test.v'
//
// and is skipped everywhere else.
func TestAllowForwardInDockerUser(t *testing.T) {
	ctx := t.Context()
	if os.Geteuid() != 0 || run(ctx, "iptables", "-N", "DOCKER-USER") != nil {
		t.Skip("needs root and iptables-nft in a network namespace of its own")
	}
	_ = run(ctx, "iptables", "-A", "DOCKER-USER", "-s", "192.0.2.1", "-j", "DROP") // the administrator's own rule
	var c linuxCfg
	for range 2 { // twice: no duplicates
		if found, err := c.AllowForward(ctx, "bg0", true); !found || err != nil {
			t.Fatal(found, err)
		}
	}
	out, err := exec.Command("iptables", "-S", "DOCKER-USER").CombinedOutput()
	if err != nil {
		t.Fatalf("iptables cannot read the chain any more: %v\n%s", err, out)
	}
	if got := string(out); strings.Count(got, "bg0") != 2 || !strings.Contains(got, "-A DOCKER-USER -i bg0 -j ACCEPT") || !strings.Contains(got, "-A DOCKER-USER -o bg0 -j ACCEPT") {
		t.Fatalf("got\n%s", got)
	}
	if _, err := c.AllowForward(ctx, "bg0", false); err != nil {
		t.Fatal(err)
	}
	out, _ = exec.Command("iptables", "-S", "DOCKER-USER").CombinedOutput()
	if got := string(out); strings.Contains(got, "bg0") || !strings.Contains(got, "192.0.2.1") {
		t.Fatalf("after removal\n%s", got)
	}
}
