package transport_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// plainConn hides the *net.UDPConn from quic-go, as the mux's encapsulating
// connection does: no path MTU discovery, the packets never grow.
type plainConn struct{ net.PacketConn }

// A packet of the tunnel MTU (the IPv6 minimum) passes both ways, also with
// a server behind a mux. At 1230 Safari's QUIC packets never reached the
// tunnel; at 1280 with quic-go's own packet size nothing that large fit.
func TestFullSizePacketsBehindAMux(t *testing.T) {
	certA, spkiA := newDevice(t, "device-a")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "dev-a"}}}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverCert, roots := newServerCert(t)
	h := &echoHandler{accepted: make(chan transport.AuthenticatedPeer, 8)}
	srv, err := transport.NewServer(transport.ServerConfig{
		PacketConn:  plainConn{udp},
		TLS:         transport.ServerTLSConfig(serverCert, lookup),
		Lookup:      lookup,
		Template:    "https://gateway.test/vpn",
		IdleTimeout: 5 * time.Second,
		KeepAlive:   time.Second,
	}, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	tun, err := transport.Dial(dctx, transport.ClientConfig{
		GatewayAddr: udp.LocalAddr().String(),
		TLS:         transport.ClientTLSConfig(certA, roots, "gateway.test"),
		Template:    "https://gateway.test/vpn",
		IdleTimeout: 5 * time.Second,
		KeepAlive:   time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tun.Close()

	pkt := ipv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("10.0.0.1"), make([]byte, transport.FitMTU-20))
	if icmp, err := tun.WritePacket(pkt); err != nil || icmp != nil {
		t.Fatalf("a %d-byte packet did not fit towards the server: err %v, icmp %d bytes", len(pkt), err, len(icmp))
	}
	buf := make([]byte, 2000)
	rd := make(chan int, 1)
	go func() {
		n, _ := tun.ReadPacket(buf)
		rd <- n
	}()
	select {
	case n := <-rd:
		if n != len(pkt) {
			t.Fatalf("echo of %d bytes, sent %d", n, len(pkt))
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the server's %d-byte echo never arrived", len(pkt))
	}
}
