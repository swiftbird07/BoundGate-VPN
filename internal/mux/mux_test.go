package mux

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func selfSigned(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

// h3Backend is a QUIC server the way control plane and hub run behind a mux.
func h3Backend(t *testing.T, id byte, name string) (addr string, roots *x509.CertPool) {
	t.Helper()
	cert, pool := selfSigned(t, name)
	pc, err := ListenBackend("127.0.0.1:0", loopback)
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc, ConnectionIDGenerator: CIDGenerator{ID: id}}
	ln, err := tr.ListenEarly(http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "%s sees %s", name, r.RemoteAddr) })}
	go srv.ServeListener(ln)
	t.Cleanup(func() { srv.Close(); tr.Close(); pc.Close() })
	return pc.LocalAddr().String(), pool
}

func startFront(t *testing.T, cfg Config) *Front {
	t.Helper()
	cfg.Listen = "127.0.0.1:0"
	cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	f, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return f
}

func h3Get(t *testing.T, front net.Addr, sni string, roots *x509.CertPool, pc net.PacketConn, versions []quic.Version) (string, error) {
	t.Helper()
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: sni},
		QUICConfig:      &quic.Config{Versions: versions, HandshakeIdleTimeout: 2 * time.Second},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			ua := front.(*net.UDPAddr)
			if pc != nil {
				return (&quic.Transport{Conn: pc}).DialEarly(ctx, ua, tlsCfg, qc)
			}
			return quic.DialAddrEarly(ctx, ua.String(), tlsCfg, qc)
		},
	}
	defer tr.Close()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	rsp, err := c.Get("https://" + sni + "/")
	if err != nil {
		return "", err
	}
	defer rsp.Body.Close()
	b, _ := io.ReadAll(rsp.Body)
	return string(b), nil
}

// Two QUIC servers with their own keys share one UDP port; the client's
// TLS verification proves it reached the right one, and the server sees the
// client's address rather than the front's.
func TestQUICRoutedByServerName(t *testing.T) {
	cplAddr, cplRoots := h3Backend(t, 1, "nodes.bg.example.com")
	hubAddr, hubRoots := h3Backend(t, 2, "hub.boundgate")
	f := startFront(t, Config{Routes: []Route{
		{Name: "control", SNI: []string{"bg.example.com", "nodes.bg.example.com"}, ID: 1, UDP: cplAddr},
		{Name: "hub", SNI: []string{"hub.boundgate"}, ID: 2, UDP: hubAddr},
	}})
	for _, v := range [][]quic.Version{{quic.Version1}, {quic.Version2}} {
		for _, tc := range []struct {
			sni   string
			roots *x509.CertPool
		}{{"nodes.bg.example.com", cplRoots}, {"hub.boundgate", hubRoots}} {
			pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
			body, err := h3Get(t, f.UDPAddr(), tc.sni, tc.roots, pc, v)
			if err != nil {
				t.Fatalf("%s (%v): %v", tc.sni, v, err)
			}
			if want := tc.sni + " sees " + pc.LocalAddr().String(); body != want {
				t.Fatalf("got %q, want %q", body, want)
			}
			pc.Close()
		}
	}
	// the hub's name must never end at the control plane: with the control
	// plane's trust roots the handshake has to fail
	if _, err := h3Get(t, f.UDPAddr(), "hub.boundgate", cplRoots, nil, nil); err == nil {
		t.Fatal("hub name verified against the control plane's certificate")
	}
	// a name nobody serves gets no answer at all
	if _, err := h3Get(t, f.UDPAddr(), "other.example.com", cplRoots, nil, nil); err == nil {
		t.Fatal("unknown server name was routed")
	}
}

// natRelay forwards UDP between a client and the front and can change its
// outward source port, like a NAT that forgot its binding.
type natRelay struct {
	in    *net.UDPConn
	out   atomic.Pointer[net.UDPConn]
	front *net.UDPAddr
	peer  atomic.Pointer[net.UDPAddr]
}

func newNATRelay(t *testing.T, front net.Addr) *natRelay {
	in, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	r := &natRelay{in: in, front: front.(*net.UDPAddr)}
	r.rebind()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := in.ReadFromUDP(buf)
			if err != nil {
				return
			}
			r.peer.Store(from)
			r.out.Load().WriteToUDP(buf[:n], r.front)
		}
	}()
	t.Cleanup(func() { in.Close(); r.out.Load().Close() })
	return r
}

func (r *natRelay) rebind() {
	out, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	old := r.out.Swap(out)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := out.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if p := r.peer.Load(); p != nil {
				r.in.WriteToUDP(buf[:n], p)
			}
		}
	}()
	if old != nil {
		old.Close()
	}
}

// An established connection keeps working when the client's address changes:
// routing follows the connection ID, not the address.
func TestQUICSurvivesAddressChange(t *testing.T) {
	hubAddr, roots := h3Backend(t, 7, "hub.boundgate")
	f := startFront(t, Config{Routes: []Route{{Name: "hub", SNI: []string{"hub.boundgate"}, ID: 7, UDP: hubAddr}}})
	relay := newNATRelay(t, f.UDPAddr())
	tr := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "hub.boundgate"},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, relay.in.LocalAddr().String(), tlsCfg, qc)
		}}
	defer tr.Close()
	c := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	get := func() string {
		rsp, err := c.Get("https://hub.boundgate/")
		if err != nil {
			t.Fatal(err)
		}
		defer rsp.Body.Close()
		b, _ := io.ReadAll(rsp.Body)
		return string(b)
	}
	before := get()
	for i := 0; i < 3; i++ {
		// the old source port is closed: an answer can only arrive if the front
		// routed the short-header packets from the new address by connection
		// ID and the server followed the client to its new address
		relay.rebind()
		if after := get(); !strings.HasPrefix(after, "hub.boundgate sees 127.0.0.1:") {
			t.Fatalf("before %q, after %q", before, after)
		}
	}
}

func tlsBackend(t *testing.T, name string, proxy bool) (string, *x509.CertPool) {
	t.Helper()
	cert, pool := selfSigned(t, name)
	var ln net.Listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if proxy {
		ln = &ProxyListener{Listener: ln, Trusted: loopback}
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "%s sees %s", name, r.RemoteAddr) }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	return addr, pool
}

func TestTCPRoutedByServerName(t *testing.T) {
	cplAddr, cplRoots := tlsBackend(t, "bg.example.com", true)
	webAddr, webRoots := tlsBackend(t, "www.example.com", false)
	f := startFront(t, Config{DefaultTCP: webAddr, Routes: []Route{
		{Name: "control", SNI: []string{"bg.example.com", "*.bg.example.com"}, TCP: cplAddr, ProxyProtocol: true},
	}})
	get := func(sni string, roots *x509.CertPool) (string, string) {
		var local string
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: sni},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, "tcp", f.TCPAddr().String())
				if err == nil {
					local = c.LocalAddr().String()
				}
				return c, err
			}}
		defer tr.CloseIdleConnections()
		rsp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + sni + "/")
		if err != nil {
			t.Fatalf("%s: %v", sni, err)
		}
		defer rsp.Body.Close()
		b, _ := io.ReadAll(rsp.Body)
		return string(b), local
	}
	// routed name, PROXY protocol: the backend sees the client
	if body, local := get("bg.example.com", cplRoots); body != "bg.example.com sees "+local {
		t.Fatalf("got %q, client was %s", body, local)
	}
	// every other name goes to the default backend untouched (it sees the front)
	if body, local := get("www.example.com", webRoots); !strings.HasPrefix(body, "www.example.com sees 127.0.0.1:") || strings.HasSuffix(body, local) {
		t.Fatalf("got %q", body)
	}
}

func TestClientHelloSNI(t *testing.T) {
	// a real ClientHello, captured from crypto/tls
	c, s := net.Pipe()
	go tls.Client(c, &tls.Config{ServerName: "Nodes.BG.example.com", InsecureSkipVerify: true}).Handshake()
	name, raw, err := readTLSClientHello(s, tcpPeekMax)
	s.Close()
	if err != nil || name != "nodes.bg.example.com" || len(raw) < 100 {
		t.Fatalf("%q %d %v", name, len(raw), err)
	}
	hello := raw[5:]
	for cut := 0; cut < len(hello); cut += 7 {
		if n, err := clientHelloSNI(hello[:cut]); err == nil && n != "nodes.bg.example.com" {
			t.Fatalf("cut at %d yields %q", cut, n)
		}
	}
	for _, bad := range [][]byte{nil, {1}, {2, 0, 0, 1, 0}, {1, 0xff, 0xff, 0xff}, append([]byte{1, 0, 0, 40}, make([]byte, 40)...)} {
		if n, err := clientHelloSNI(bad); err == nil {
			t.Fatalf("%v yields %q", bad, n)
		}
	}
}

func FuzzRouteUDP(f *testing.F) {
	f.Add([]byte{0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x40, 0x20})
	f.Add([]byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	fr := &Front{cfg: Config{}, byID: map[byte]*backend{}, byName: map[string]*backend{}, wild: map[string]*backend{}, initial: map[flowKey]*flow{}}
	client := netip.MustParseAddrPort("192.0.2.1:4000")
	f.Fuzz(func(t *testing.T, b []byte) {
		fr.routeUDP(client, b)
		_, _ = clientHelloSNI(b)
		var cb cryptoBuf
		_ = cryptoFrames(b, &cb)
	})
}
