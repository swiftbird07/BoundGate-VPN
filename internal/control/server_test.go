package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/snapshot"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicecert"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey/softkey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/servercert"
)

// TestSNISplit checks that one listener serves admins (no client cert) and
// nodes (client cert required) depending on the server name.
func TestSNISplit(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	store, err := db.Open(ctx, filepath.Join(dir, "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	logs, _ := logging.Open(logging.Options{Dir: filepath.Join(dir, "logs")})
	h := api.New(api.Deps{DB: store, Snap: snapshot.New(store), Logs: logs})

	adminCert, _, _ := servercert.LoadOrCreate(filepath.Join(dir, "a.crt"), filepath.Join(dir, "a.key"), []string{"control"})
	nodeCert, _, _ := servercert.LoadOrCreate(filepath.Join(dir, "n.crt"), filepath.Join(dir, "n.key"), []string{"nodes.control"})
	srv := httptest.NewUnstartedServer(h.Root("nodes.control"))
	srv.TLS = TLSConfig(adminCert, nodeCert, "nodes.control", []string{"http/1.1"})
	srv.StartTLS()
	defer srv.Close()

	adminRoots := x509.NewCertPool()
	adminRoots.AddCert(adminCert.Leaf)
	nodeRoots := x509.NewCertPool()
	nodeRoots.AddCert(nodeCert.Leaf)

	// admin name, no client cert: reaches the admin API (401 without token)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: adminRoots, ServerName: "control"}}}
	rsp, err := c.Get(srv.URL + "/api/v1/admin/me")
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin path: %d", rsp.StatusCode)
	}
	// admin name cannot reach node routes
	rsp, _ = c.Get(srv.URL + "/api/v1/node/enroll/status")
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("node route via admin name: %d", rsp.StatusCode)
	}

	// node name without a client cert: handshake fails
	c = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: nodeRoots, ServerName: "nodes.control"}}}
	if _, err := c.Get(srv.URL + "/api/v1/node/enroll/status"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("node name without cert: %v", err)
	}

	// node name with a device cert: node API answers
	key, _ := softkey.New(filepath.Join(dir, "k")).Open(ctx)
	dev, _ := devicecert.SelfSigned(key, "n")
	c = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: nodeRoots, ServerName: "nodes.control", Certificates: []tls.Certificate{dev}}}}
	rsp, err = c.Get(srv.URL + "/api/v1/node/enroll/status")
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusNotFound { // unknown key
		t.Fatalf("node path: %d", rsp.StatusCode)
	}
	// and the node name serves the node cert, not the admin cert
	if rsp.TLS.PeerCertificates[0].Subject.String() != nodeCert.Leaf.Subject.String() {
		t.Fatalf("node name served %s", rsp.TLS.PeerCertificates[0].Subject)
	}
}

// With ACME the admin certificate comes from a callback; the node name must
// keep its own key and its client-certificate requirement.
func TestSNISplitWithACMECallback(t *testing.T) {
	dir := t.TempDir()
	adminCert, _, _ := servercert.LoadOrCreate(filepath.Join(dir, "a.crt"), filepath.Join(dir, "a.key"), []string{"bg.example.com"})
	nodeCert, _, _ := servercert.LoadOrCreate(filepath.Join(dir, "n.crt"), filepath.Join(dir, "n.key"), []string{"nodes.bg.example.com"})
	asked := ""
	get := func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { asked = h.ServerName; return &adminCert, nil }
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	srv.TLS = TLSConfigACME(get, nodeCert, "nodes.bg.example.com", []string{"http/1.1", "acme-tls/1"})
	srv.StartTLS()
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(adminCert.Leaf)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "bg.example.com"}}}
	rsp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()
	if asked != "bg.example.com" {
		t.Fatalf("callback asked for %q", asked)
	}

	asked = ""
	nodeRoots := x509.NewCertPool()
	nodeRoots.AddCert(nodeCert.Leaf)
	c = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: nodeRoots, ServerName: "nodes.bg.example.com"}}}
	if _, err := c.Get(srv.URL); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("node name without a client certificate: %v", err)
	}
	if asked != "" {
		t.Fatal("the ACME callback was asked for the node name")
	}
}

// Every phase of a TCP connection is bounded, and the answer to the
// longest long-poll still fits.
func TestTCPServerTimeouts(t *testing.T) {
	s := newTCPServer(":443", http.NotFoundHandler(), nil)
	if s.ReadHeaderTimeout <= 0 || s.ReadTimeout <= 0 || s.WriteTimeout <= 0 || s.IdleTimeout <= 0 || s.MaxHeaderBytes <= 0 {
		t.Fatalf("an unbounded phase: %+v", s)
	}
	if s.WriteTimeout <= api.MaxLongPoll {
		t.Fatalf("write timeout %v cuts off a long-poll of %v", s.WriteTimeout, api.MaxLongPoll)
	}
	if s.ReadHeaderTimeout > s.ReadTimeout {
		t.Fatal("headers may take longer than the whole request")
	}
}
