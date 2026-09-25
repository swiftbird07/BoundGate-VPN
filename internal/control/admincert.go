package control

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
)

// certReloader serves the admin certificate from files and picks up a new
// pair when the files change, so an external ACME client (DNS-01 through
// lego, certbot, acme.sh) can renew without a restart. The files are
// checked at most once per interval, at handshake time.
type certReloader struct {
	certFile, keyFile string
	interval          time.Duration

	mu      sync.Mutex
	cert    *tls.Certificate
	mtime   time.Time
	checked time.Time
	onLoad  func(*tls.Certificate, error)
}

func newCertReloader(certFile, keyFile string, initial tls.Certificate, interval time.Duration) *certReloader {
	r := &certReloader{certFile: certFile, keyFile: keyFile, interval: interval, cert: &initial}
	r.mtime = r.stat()
	r.checked = time.Now()
	return r
}

func (r *certReloader) stat() time.Time {
	var t time.Time
	for _, f := range []string{r.certFile, r.keyFile} {
		if st, err := os.Stat(f); err == nil && st.ModTime().After(t) {
			t = st.ModTime()
		}
	}
	return t
}

// Get is an AdminCertFunc.
func (r *certReloader) Get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := time.Now(); now.Sub(r.checked) >= r.interval {
		r.checked = now
		if m := r.stat(); m.After(r.mtime) {
			c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
			if err == nil {
				r.cert, r.mtime = &c, m
			}
			if r.onLoad != nil {
				r.onLoad(&c, err)
			}
		}
	}
	return r.cert, nil
}

// adminAllowed reports whether a handshake or request for the admin name
// may proceed from addr. An empty list allows everyone. ACME's TLS-ALPN-01
// validation (a handshake with ALPN acme-tls/1 that never reaches HTTP)
// comes from the CA's vantage points and is always let through.
func adminAllowed(allow []netip.Prefix, addr net.Addr, protos []string) bool {
	if len(allow) == 0 || slices.Contains(protos, acme.ALPNProto) {
		return true
	}
	if addr == nil {
		return false
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// adminGate enforces admin_allow per request on every server name but the
// node name. From an address outside the list exactly two requests pass:
// GET of the OIDC callback, because users sign in to their nodes from
// anywhere and the identity provider sends their browser back there, and
// POST of the confirmation that page asks for. They are marked
// (api.WithAdminDenied), so the callback still refuses an admin login from
// outside the list. Everything else gets 403.
//
// The check is no longer made at the TLS handshake: a handshake does not know
// the path, and refusing it there cut off every user's sign-in from outside
// the list (seen with an iPhone on a mobile network).
func adminGate(allow []netip.Prefix, nodeServerName string, onDeny func(net.Addr), inner http.Handler) http.Handler {
	if len(allow) == 0 {
		return inner
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && r.TLS.ServerName == nodeServerName {
			inner.ServeHTTP(w, r)
			return
		}
		addr := strAddr(r.RemoteAddr)
		if adminAllowed(allow, addr, nil) {
			inner.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == api.OIDCCallbackPath || r.Method == http.MethodPost && r.URL.Path == api.OIDCConfirmPath {
			inner.ServeHTTP(w, api.WithAdminDenied(r))
			return
		}
		if onDeny != nil {
			onDeny(addr)
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}

type strAddr string

func (a strAddr) Network() string { return "tcp" }
func (a strAddr) String() string  { return string(a) }
