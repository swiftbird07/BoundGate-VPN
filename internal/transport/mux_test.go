package transport_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/mux"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// A hub behind a mux: the tunnel (mTLS with device keys, CONNECT-IP, QUIC
// datagrams in both directions) works through the front unchanged, the hub
// still authenticates the device itself and still sees where it comes from.
func TestTunnelThroughMux(t *testing.T) {
	certA, spkiA := newDevice(t, "device-a")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "dev-a"}}}
	serverCert, roots := newServerCert(t)

	pc, err := mux.ListenBackend("127.0.0.1:0", []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	if err != nil {
		t.Fatal(err)
	}
	h := &echoHandler{accepted: make(chan transport.AuthenticatedPeer, 8)}
	srv, err := transport.NewServer(transport.ServerConfig{
		PacketConn: pc, ConnIDGenerator: mux.CIDGenerator{ID: 2},
		TLS: transport.ServerTLSConfig(serverCert, lookup), Lookup: lookup, Template: "https://gateway.test/vpn",
		IdleTimeout: 5 * time.Second, KeepAlive: time.Second,
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

	front, err := mux.New(mux.Config{Listen: "127.0.0.1:0", Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Routes: []mux.Route{{Name: "hub", SNI: []string{"gateway.test"}, ID: 2, UDP: pc.LocalAddr().String()}}})
	if err != nil {
		t.Fatal(err)
	}
	fdone := make(chan struct{})
	go func() { defer close(fdone); _ = front.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done; <-fdone })

	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	tun, err := transport.Dial(dctx, transport.ClientConfig{GatewayAddr: front.UDPAddr().String(),
		TLS: transport.ClientTLSConfig(certA, roots, "gateway.test"), Template: "https://gateway.test/vpn", IdleTimeout: 5 * time.Second, KeepAlive: time.Second})
	if err != nil {
		t.Fatalf("dial through the mux: %v", err)
	}
	defer tun.Close()
	select {
	case peer := <-h.accepted:
		if peer.DeviceID() != "dev-a" || peer.SPKI() != spkiA || !peer.SourceIP().IsLoopback() {
			t.Fatalf("unexpected peer %v from %v", peer, peer.SourceIP())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler never accepted")
	}
	for i := 0; i < 20; i++ {
		pkt := ipv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("10.0.0.1"), []byte("through the mux"))
		if _, err := tun.WritePacket(pkt); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2000)
		n, err := tun.ReadPacket(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[20:n]) != "through the mux" {
			t.Fatalf("echo %d: %x", i, buf[:n])
		}
	}

	// a device the hub does not know fails at the hub's handshake, as without a mux
	certB, _ := newDevice(t, "device-b")
	if _, err := transport.Dial(dctx, transport.ClientConfig{GatewayAddr: front.UDPAddr().String(),
		TLS: transport.ClientTLSConfig(certB, roots, "gateway.test"), Template: "https://gateway.test/vpn"}); err == nil {
		t.Fatal("unknown device got a tunnel through the mux")
	}
}
