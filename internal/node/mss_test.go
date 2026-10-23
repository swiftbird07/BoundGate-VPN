package node

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/flow"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// syn is an IPv4 TCP SYN (or SYN-ACK) announcing an MSS of 1460.
func syn(src, dst string, ack bool) []byte {
	pkt := make([]byte, 44)
	pkt[0], pkt[8], pkt[9] = 0x45, 64, netparse.ProtoTCP
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(pkt[12:], s[:])
	copy(pkt[16:], d[:])
	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	tcp[12] = 6 << 4 // 24 bytes: the header and one option
	tcp[13] = netparse.TCPSyn
	if ack {
		tcp[13] |= netparse.TCPAck
	}
	tcp[20], tcp[21] = 2, 4 // MSS
	binary.BigEndian.PutUint16(tcp[22:], 1460)
	return pkt
}

func announcedMSS(t *testing.T, s *session, pkt []byte, origin flow.Origin) uint16 {
	t.Helper()
	h, ok := netparse.Parse(pkt)
	if !ok {
		t.Fatal("the test packet does not parse")
	}
	netparse.ClampMSS(h, pkt, s.mss(h, origin))
	return binary.BigEndian.Uint16(pkt[42:])
}

// TCP with another spoke is told the relayed path's segment size from the
// first SYN on, in both directions: it may move onto a relayed path at any
// moment, and the ICMP that would shrink it later does not reach a host in a
// LAN behind a subnet router (#16, measured at the Orkus site). Everything
// else keeps what fits the tunnel device.
func TestTCPWithASpokeIsToldTheRelaysSegmentSize(t *testing.T) {
	hub := registry.Node{ID: "hub", OverlayIP: netip.MustParseAddr("10.25.0.2"), PublicAddr: "vpn.test:443",
		Roles: []registry.Role{registry.RoleHub}, Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("10.20.0.0/16")},
			{Prefix: netip.MustParsePrefix("0.0.0.0/0")}}}
	router := registry.Node{ID: "orkus", OverlayIP: netip.MustParseAddr("10.25.77.10"),
		Prefixes: []registry.Prefix{{Prefix: netip.MustParsePrefix("192.168.3.0/24")}}}
	self := registry.Node{ID: "pcore", OverlayIP: netip.MustParseAddr("10.25.0.10")}
	snap := &registry.Snapshot{Self: self, Peers: []registry.Node{hub, router}}

	s := &session{n: &Node{cfg: Config{MTU: transport.FitMTU}}}
	s.paths = &pathManager{s: s}
	s.paths.rebuild(snap)
	relay := uint16(transport.RelayPathMTU - 40)
	device := uint16(transport.FitMTU - 40)
	local := flow.Origin{Local: true}
	fromPeer := flow.Origin{Principal: router.ID}

	for _, c := range []struct {
		what   string
		pkt    []byte
		origin flow.Origin
		want   uint16
	}{
		{"SYN into the LAN behind a spoke", syn("10.25.0.10", "192.168.3.5", false), local, relay},
		{"SYN to a spoke itself", syn("10.25.0.10", "10.25.77.10", false), local, relay},
		{"SYN-ACK coming back from that LAN", syn("192.168.3.5", "10.25.0.10", true), fromPeer, relay},
		{"SYN-ACK this node sends back to a spoke", syn("10.25.0.10", "10.25.77.10", true), local, relay},
		{"SYN into the hub's own network", syn("10.25.0.10", "10.20.1.33", false), local, device},
		{"SYN to the internet, through the exit", syn("10.25.0.10", "93.184.216.34", false), local, device},
		{"SYN to the hub", syn("10.25.0.10", "10.25.0.2", false), local, device},
	} {
		if got := announcedMSS(t, s, c.pkt, c.origin); got != c.want {
			t.Errorf("%s: MSS %d, want %d", c.what, got, c.want)
		}
	}

	// a node that takes no part in paths (paths.disabled) never moves onto
	// one, so it keeps the device's segment size
	s.paths = nil
	if got := announcedMSS(t, s, syn("10.25.0.10", "192.168.3.5", false), local); got != device {
		t.Errorf("without paths: MSS %d, want %d", got, device)
	}
}
