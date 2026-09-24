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

// Without keep-alives on either side (a phone in power save, a hub that
// leaves keeping alive to the clients) a tunnel carries packets as usual
// and, once nothing uses it, ends by its idle timeout: nothing is sent to
// keep it open. Over QUIC and over the TCP fallback.
func TestQuietTunnelEndsWhenIdle(t *testing.T) {
	certA, spkiA := newDevice(t, "device-a")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "dev-a"}}}
	serverCert, roots := newServerCert(t)
	h := &echoHandler{accepted: make(chan transport.AuthenticatedPeer, 8)}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	const idle = 1500 * time.Millisecond
	srv, err := transport.NewServer(transport.ServerConfig{
		Addr: "127.0.0.1:0", TLS: transport.ServerTLSConfig(serverCert, lookup), Lookup: lookup,
		Template: "https://gateway.test/vpn", IdleTimeout: idle, KeepAlive: -1, TCPListener: tcpLn,
	}, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	for _, tc := range []struct {
		name string
		dial func(context.Context, transport.ClientConfig) (*transport.ClientTunnel, error)
		addr string
	}{
		{"quic", transport.Dial, srv.LocalAddr().String()},
		{"tcp", transport.DialTCP, tcpLn.Addr().String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
			defer dcancel()
			tun, err := tc.dial(dctx, transport.ClientConfig{
				GatewayAddr: tc.addr, TLS: transport.ClientTLSConfig(certA, roots, "gateway.test"),
				Template: "https://gateway.test/vpn", IdleTimeout: idle, KeepAlive: -1,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer tun.Close()
			pkt := ipv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("10.0.0.1"), []byte("hello"))
			if _, err := tun.WritePacket(pkt); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 2000)
			if _, err := tun.ReadPacket(buf); err != nil {
				t.Fatal(err)
			}
			select {
			case <-tun.Done():
			case <-time.After(idle + 5*time.Second):
				t.Fatal("an idle tunnel without keep-alives stayed open")
			}
		})
	}
}
