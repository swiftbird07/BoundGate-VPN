package control

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicecert"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey/softkey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/mux"
)

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// The whole control plane behind a mux: the admin name over TCP (with PROXY
// protocol) and the node channel over HTTP/3 with a device certificate.
func TestControlPlaneBehindMux(t *testing.T) {
	dir := t.TempDir()
	logs, _ := logging.Open(logging.Options{Dir: filepath.Join(dir, "logs")})
	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Listen: addr, ServerName: "bg.test", TLSCert: filepath.Join(dir, "a.crt"), TLSKey: filepath.Join(dir, "a.key"),
			NodeCert: filepath.Join(dir, "n.crt"), NodeKey: filepath.Join(dir, "n.key"), DBPath: filepath.Join(dir, "c.db"), Logs: logs, NoSPA: true,
			BehindMux: &BehindMux{ID: 1, Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}})
	}()
	front, err := mux.New(mux.Config{Listen: "127.0.0.1:0", Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Routes: []mux.Route{{Name: "control", SNI: []string{"bg.test", "nodes.bg.test"}, ID: 1, UDP: addr, TCP: addr, ProxyProtocol: true}}})
	if err != nil {
		t.Fatal(err)
	}
	fdone := make(chan struct{})
	go func() { defer close(fdone); _ = front.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-fdone
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("control plane did not stop")
		}
	})

	// admin name, TCP
	tcp := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "bg.test", InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", front.TCPAddr().String())
		}}}
	var rsp *http.Response
	for i := 0; i < 50; i++ { // the control plane needs a moment to listen
		if rsp, err = tcp.Get("https://bg.test/api/v1/admin/me"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin API through the mux: %d", rsp.StatusCode)
	}

	// node channel, HTTP/3, device certificate
	key, err := softkey.New(filepath.Join(dir, "dev.key")).Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := devicecert.SelfSigned(key, "mac")
	if err != nil {
		t.Fatal(err)
	}
	h3 := &http3.Transport{TLSClientConfig: &tls.Config{ServerName: "nodes.bg.test", InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}},
		Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, front.UDPAddr().String(), tc, qc)
		}}
	defer h3.Close()
	rsp, err = (&http.Client{Transport: h3, Timeout: 5 * time.Second}).Get("https://nodes.bg.test/api/v1/node/enroll/status")
	if err != nil {
		t.Fatalf("node channel over HTTP/3 through the mux: %v", err)
	}
	body, _ := io.ReadAll(rsp.Body)
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusNotFound || !strings.Contains(string(body), "unknown") {
		t.Fatalf("enroll status: %d %s", rsp.StatusCode, body)
	}
}
