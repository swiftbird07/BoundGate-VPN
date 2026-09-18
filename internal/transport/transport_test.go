package transport_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicecert"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey/softkey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// staticLookup is an in-memory registry for tests.
type staticLookup struct {
	mu sync.Mutex
	m  map[devicekey.SPKIHash]transport.DeviceInfo
}

func (l *staticLookup) LookupSPKI(h devicekey.SPKIHash) (transport.DeviceInfo, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	d, ok := l.m[h]
	return d, ok
}

func (l *staticLookup) remove(h devicekey.SPKIHash) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, h)
}

// echoHandler assigns an address and echoes packets with src/dst swapped.
type echoHandler struct {
	accepted chan transport.AuthenticatedPeer
	refuse   int // HTTP status to refuse every tunnel with, 0 = accept
}

func (h *echoHandler) Accept(_ context.Context, peer transport.AuthenticatedPeer) (transport.TunnelConfig, int, error) {
	if h.refuse != 0 {
		return transport.TunnelConfig{}, h.refuse, nil
	}
	h.accepted <- peer
	return transport.TunnelConfig{
		Assigned: []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")},
		Routes: []connectip.IPRoute{{
			StartIP: netip.MustParseAddr("10.0.0.0"),
			EndIP:   netip.MustParseAddr("10.255.255.255"),
		}},
	}, http.StatusOK, nil
}

func (h *echoHandler) Serve(ctx context.Context, t *transport.Tunnel) {
	buf := make([]byte, 2000)
	for {
		n, err := t.ReadPacket(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		// swap IPv4 src/dst so the reply targets the assigned address
		copy(pkt[12:16], buf[16:20])
		copy(pkt[16:20], buf[12:16])
		setIPv4Checksum(pkt)
		if _, err := t.WritePacket(pkt); err != nil {
			return
		}
	}
}

func (h *echoHandler) Release(transport.AuthenticatedPeer, transport.TunnelConfig) {}

func newDevice(t *testing.T, name string) (tls.Certificate, devicekey.SPKIHash) {
	t.Helper()
	dir := t.TempDir()
	key, err := softkey.New(filepath.Join(dir, "key.pem")).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := devicecert.SelfSigned(key, name)
	if err != nil {
		t.Fatal(err)
	}
	h, err := devicekey.HashPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return cert, h
}

func newServerCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gateway.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"gateway.test"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, pool
}

type testEnv struct {
	srv     *transport.Server
	lookup  *staticLookup
	h       *echoHandler
	roots   *x509.CertPool
	addr    string
	tcpAddr string
	cancel  context.CancelFunc
}

func startServer(t *testing.T, lookup *staticLookup) *testEnv {
	t.Helper()
	serverCert, roots := newServerCert(t)
	h := &echoHandler{accepted: make(chan transport.AuthenticatedPeer, 8)}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := transport.NewServer(transport.ServerConfig{
		Addr:        "127.0.0.1:0",
		TLS:         transport.ServerTLSConfig(serverCert, lookup),
		Lookup:      lookup,
		Template:    "https://gateway.test/vpn",
		IdleTimeout: 5 * time.Second,
		KeepAlive:   time.Second,
		TCPListener: tcpLn,
	}, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ctx); err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return &testEnv{srv: srv, lookup: lookup, h: h, roots: roots, addr: srv.LocalAddr().String(), tcpAddr: tcpLn.Addr().String(), cancel: cancel}
}

func (e *testEnv) dial(t *testing.T, cert tls.Certificate) (*transport.ClientTunnel, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return transport.Dial(ctx, transport.ClientConfig{
		GatewayAddr: e.addr,
		TLS:         transport.ClientTLSConfig(cert, e.roots, "gateway.test"),
		Template:    "https://gateway.test/vpn",
		IdleTimeout: 5 * time.Second,
		KeepAlive:   time.Second,
	})
}

// dialTCP is dial over the TCP fallback: same TLS material, same template.
func (e *testEnv) dialTCP(t *testing.T, cert tls.Certificate) (*transport.ClientTunnel, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return transport.DialTCP(ctx, transport.ClientConfig{
		GatewayAddr: e.tcpAddr,
		TLS:         transport.ClientTLSConfig(cert, e.roots, "gateway.test"),
		Template:    "https://gateway.test/vpn",
		IdleTimeout: 5 * time.Second,
		KeepAlive:   200 * time.Millisecond,
	})
}

func TestApprovedDeviceGetsTunnelAndEcho(t *testing.T) {
	certA, spkiA := newDevice(t, "device-a")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{
		spkiA: {ID: "dev-a", HardwareBound: false},
	}}
	env := startServer(t, lookup)

	tun, err := env.dial(t, certA)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tun.Close()

	select {
	case peer := <-env.h.accepted:
		if peer.DeviceID() != "dev-a" || peer.SPKI() != spkiA {
			t.Fatalf("unexpected peer %v", peer)
		}
		if !peer.SourceIP().IsLoopback() {
			t.Fatalf("source ip %v", peer.SourceIP())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler never accepted")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	prefixes, err := tun.LocalPrefixes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 1 || prefixes[0] != netip.MustParsePrefix("100.96.0.2/32") {
		t.Fatalf("prefixes %v", prefixes)
	}
	routes, err := tun.Routes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].StartIP != netip.MustParseAddr("10.0.0.0") {
		t.Fatalf("routes %v", routes)
	}

	pkt := ipv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("10.0.0.1"), []byte("hello"))
	if _, err := tun.WritePacket(pkt); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	n, err := tun.ReadPacket(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := buf[:n]
	if netip.AddrFrom4([4]byte(got[12:16])) != netip.MustParseAddr("10.0.0.1") ||
		netip.AddrFrom4([4]byte(got[16:20])) != netip.MustParseAddr("100.96.0.2") ||
		string(got[20:]) != "hello" {
		t.Fatalf("unexpected echo %x", got)
	}
}

func TestUnknownDeviceFailsHandshake(t *testing.T) {
	certA, spkiA := newDevice(t, "device-a")
	certB, _ := newDevice(t, "device-b")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "dev-a"}}}
	env := startServer(t, lookup)

	if _, err := env.dial(t, certB); err == nil {
		t.Fatal("unapproved device got a tunnel")
	}
	select {
	case p := <-env.h.accepted:
		t.Fatalf("handler saw a peer for an unapproved device: %v", p)
	default:
	}
	// the approved one still works afterwards
	tun, err := env.dial(t, certA)
	if err != nil {
		t.Fatalf("approved device: %v", err)
	}
	tun.Close()
}

func TestCloseDeviceRevokesLiveTunnel(t *testing.T) {
	certA, spkiA := newDevice(t, "device-a")
	certB, spkiB := newDevice(t, "device-b")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{
		spkiA: {ID: "dev-a"}, spkiB: {ID: "dev-b"},
	}}
	env := startServer(t, lookup)

	tunA, err := env.dial(t, certA)
	if err != nil {
		t.Fatal(err)
	}
	defer tunA.Close()
	tunB, err := env.dial(t, certB)
	if err != nil {
		t.Fatal(err)
	}
	defer tunB.Close()
	<-env.h.accepted
	<-env.h.accepted

	// revoke A: registry forgets it and the gateway closes its tunnels
	env.lookup.remove(spkiA)
	if n := env.srv.CloseDevice("dev-a", transport.ErrCodeRevoked, "unenrolled"); n != 1 {
		t.Fatalf("closed %d tunnels, want 1", n)
	}
	select {
	case <-tunA.Done():
		code, ok := transport.CloseCode(tunA.Err())
		if !ok || code != transport.ErrCodeRevoked {
			t.Fatalf("close reason %v", tunA.Err())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoked tunnel still open")
	}
	select {
	case <-tunB.Done():
		t.Fatalf("other device's tunnel was closed: %v", tunB.Err())
	default:
	}
	// reconnect must fail at the handshake now
	if _, err := env.dial(t, certA); err == nil {
		t.Fatal("revoked device reconnected")
	}
	if ids := env.srv.ActiveDevices(); len(ids) != 1 || ids[0] != "dev-b" {
		t.Fatalf("active devices %v", ids)
	}
}

func TestPeerFromTLSStateRejectsUnknownAndBadCerts(t *testing.T) {
	certA, spkiA := newDevice(t, "device-a")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spkiA: {ID: "dev-a", HardwareBound: true}}}
	st := &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{certA.Leaf}}
	peer, err := transport.PeerFromTLSState(st, lookup, netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if peer.DeviceID() != "dev-a" || !peer.HardwareBound() {
		t.Fatalf("peer %v", peer)
	}
	lookup.remove(spkiA)
	if _, err := transport.PeerFromTLSState(st, lookup, netip.Addr{}); !errors.Is(err, transport.ErrUnknownDevice) {
		t.Fatalf("want ErrUnknownDevice, got %v", err)
	}
	if _, err := transport.PeerFromTLSState(&tls.ConnectionState{}, lookup, netip.Addr{}); !errors.Is(err, transport.ErrNotAuthenticated) {
		t.Fatalf("want ErrNotAuthenticated, got %v", err)
	}
	// two certs (a chain) are not a device certificate
	st2 := &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{certA.Leaf, certA.Leaf}}
	if _, err := transport.PeerFromTLSState(st2, lookup, netip.Addr{}); !errors.Is(err, transport.ErrBadClientCert) {
		t.Fatalf("want ErrBadClientCert, got %v", err)
	}
	// RSA keys are rejected regardless of registry
	serverCert, _ := newServerCert(t)
	_ = serverCert
	if _, err := transport.UnverifiedSPKI(st); err != nil {
		t.Fatal(err)
	}
}

// ipv4Packet builds a minimal IPv4/UDP-less packet: header + raw payload.
func ipv4Packet(src, dst netip.Addr, payload []byte) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 253 // experimental protocol number
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	copy(p[20:], payload)
	setIPv4Checksum(p)
	return p
}

func setIPv4Checksum(p []byte) {
	p[10], p[11] = 0, 0
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
}
