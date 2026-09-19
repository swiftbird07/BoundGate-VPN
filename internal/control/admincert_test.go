package control

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/servercert"
)

// admin_allow: the admin name's handshake fails from an address outside the
// list (no certificate is served), the node name is untouched, and an ACME
// validation handshake passes regardless.
func TestAdminAllowlist(t *testing.T) {
	dir := t.TempDir()
	adminCert, _, _ := servercert.LoadOrCreate(filepath.Join(dir, "a.crt"), filepath.Join(dir, "a.key"), []string{"bg.example.com"})
	nodeCert, _, _ := servercert.LoadOrCreate(filepath.Join(dir, "n.crt"), filepath.Join(dir, "n.key"), []string{"nodes.bg.example.com"})
	get := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &adminCert, nil }
	roots := x509.NewCertPool()
	roots.AddCert(adminCert.Leaf)
	nodeRoots := x509.NewCertPool()
	nodeRoots.AddCert(nodeCert.Leaf)

	serve := func(allow []netip.Prefix) *httptest.Server {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		cfg := TLSConfigACME(get, nodeCert, "nodes.bg.example.com", []string{"http/1.1", "acme-tls/1"})
		srv.TLS = restrictAdmin(cfg, "nodes.bg.example.com", allow, nil)
		srv.StartTLS()
		return srv
	}
	adminGet := func(srv *httptest.Server) error {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "bg.example.com"}}}
		rsp, err := c.Get(srv.URL)
		if err == nil {
			rsp.Body.Close()
		}
		return err
	}

	// not on the list: the handshake itself fails
	srv := serve([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if err := adminGet(srv); err == nil {
		t.Fatal("admin name served to an address outside admin_allow")
	}
	// the node name still answers (with the usual client-certificate demand)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: nodeRoots, ServerName: "nodes.bg.example.com"}}}
	if _, err := c.Get(srv.URL); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("node name: %v", err)
	}
	// an ACME validation handshake is let through to the certificate callback
	conn, err := tls.Dial("tcp", strings.TrimPrefix(srv.URL, "https://"), &tls.Config{RootCAs: roots, ServerName: "bg.example.com", NextProtos: []string{"acme-tls/1"}})
	if err != nil {
		t.Fatalf("acme-tls/1 handshake refused: %v", err)
	}
	conn.Close()
	srv.Close()

	// on the list: served
	srv = serve([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")})
	if err := adminGet(srv); err != nil {
		t.Fatalf("admin name refused from an allowed address: %v", err)
	}
	srv.Close()

	// the HTTP-level check on its own
	if adminAllowed([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, strAddr("10.1.2.3:4444"), nil) != true ||
		adminAllowed([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, strAddr("[::ffff:10.1.2.3]:4444"), nil) != true ||
		adminAllowed([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, strAddr("192.0.2.1:1"), nil) != false ||
		adminAllowed([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil, nil) != false ||
		adminAllowed(nil, strAddr("192.0.2.1:1"), nil) != true {
		t.Fatal("adminAllowed")
	}
}

// The admin certificate is re-read when its files change: what an
// external DNS-01 client does at renewal.
func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "a.crt"), filepath.Join(dir, "a.key")
	first, _, _ := servercert.LoadOrCreate(crt, key, []string{"one.example.com"})
	r := newCertReloader(crt, key, first, 10*time.Millisecond)
	if c, _ := r.Get(nil); c.Leaf.DNSNames[0] != "one.example.com" {
		t.Fatal("initial certificate")
	}
	// a renewal: new files, newer mtime
	os.Remove(crt)
	os.Remove(key)
	if _, _, err := servercert.LoadOrCreate(crt, key, []string{"two.example.com"}); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	os.Chtimes(crt, future, future)
	os.Chtimes(key, future, future)
	time.Sleep(20 * time.Millisecond)
	c, _ := r.Get(nil)
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	if leaf.DNSNames[0] != "two.example.com" {
		t.Fatalf("not reloaded: %v", leaf.DNSNames)
	}
	// broken files keep the old pair
	os.WriteFile(key, []byte("garbage"), 0o600)
	later := future.Add(2 * time.Second)
	os.Chtimes(key, later, later)
	time.Sleep(20 * time.Millisecond)
	c, _ = r.Get(nil)
	leaf, _ = x509.ParseCertificate(c.Certificate[0])
	if leaf.DNSNames[0] != "two.example.com" {
		t.Fatalf("broken files replaced the certificate: %v", leaf.DNSNames)
	}
}
