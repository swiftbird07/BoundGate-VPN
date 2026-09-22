package control

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/servercert"
)

// admin_allow: from an address outside the list the admin name answers 403
// to everything but GET of the sign-in callback, which passes marked as
// "admin denied"; the node name is untouched; on the list, everything passes.
func TestAdminAllowlist(t *testing.T) {
	var sawDenied bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawDenied = api.AdminDeniedForTest(r)
		w.WriteHeader(http.StatusNoContent)
	})
	outside := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	var denied int
	gate := adminGate(outside, "nodes.bg.example.com", func(net.Addr) { denied++ }, inner)
	do := func(h http.Handler, method, path, sni string) int {
		r := httptest.NewRequest(method, "https://bg.example.com"+path, nil)
		r.RemoteAddr = "192.0.2.7:5555"
		r.TLS = &tls.ConnectionState{ServerName: sni}
		w := httptest.NewRecorder()
		sawDenied = false
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := do(gate, "GET", "/", "bg.example.com"); c != http.StatusForbidden {
		t.Fatalf("admin UI from outside: %d", c)
	}
	if c := do(gate, "GET", "/api/v1/admin/nodes", "bg.example.com"); c != http.StatusForbidden {
		t.Fatalf("admin API from outside: %d", c)
	}
	if c := do(gate, "POST", api.OIDCCallbackPath, "bg.example.com"); c != http.StatusForbidden {
		t.Fatalf("POST to the callback from outside: %d", c)
	}
	if c := do(gate, "GET", api.OIDCCallbackPath+"?state=x&code=y", "bg.example.com"); c != http.StatusNoContent || !sawDenied {
		t.Fatalf("user sign-in callback from outside: %d, marked %v", c, sawDenied)
	}
	if c := do(gate, "GET", "/api/v1/node/snapshot", "nodes.bg.example.com"); c != http.StatusNoContent || sawDenied {
		t.Fatalf("node name: %d", c)
	}
	if denied != 3 {
		t.Fatalf("denials logged: %d", denied)
	}
	inside := adminGate([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, "nodes.bg.example.com", nil, inner)
	if c := do(inside, "GET", api.OIDCCallbackPath, "bg.example.com"); c != http.StatusNoContent || sawDenied {
		t.Fatalf("callback from an allowed address: %d, marked %v", c, sawDenied)
	}
	if c := do(inside, "GET", "/", "bg.example.com"); c != http.StatusNoContent {
		t.Fatalf("admin UI from an allowed address: %d", c)
	}

	if adminAllowed(outside, strAddr("10.1.2.3:4444"), nil) != true ||
		adminAllowed(outside, strAddr("[::ffff:10.1.2.3]:4444"), nil) != true ||
		adminAllowed(outside, strAddr("192.0.2.1:1"), nil) != false ||
		adminAllowed(outside, nil, nil) != false ||
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
