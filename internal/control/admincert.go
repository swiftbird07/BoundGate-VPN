package control

import (
	"crypto/tls"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
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

// errAdminNotAllowed fails the handshake: the client gets an alert and no
// certificate, not even the admin name's.
type errAdminNotAllowed struct{ addr net.Addr }

func (e errAdminNotAllowed) Error() string {
	return "control: admin UI not allowed from " + e.addr.String()
}

// restrictAdmin wraps a split TLS configuration so that handshakes for
// anything but the node name are refused unless the client address is on
// the list.
func restrictAdmin(cfg *tls.Config, nodeServerName string, allow []netip.Prefix, onDeny func(net.Addr)) *tls.Config {
	if len(allow) == 0 {
		return cfg
	}
	split := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != nodeServerName {
			var addr net.Addr
			if hello.Conn != nil {
				addr = hello.Conn.RemoteAddr()
			}
			if !adminAllowed(allow, addr, hello.SupportedProtos) {
				if onDeny != nil {
					onDeny(addr)
				}
				if addr == nil {
					addr = strAddr("unknown")
				}
				return nil, errAdminNotAllowed{addr}
			}
		}
		return split(hello)
	}
	return cfg
}

type strAddr string

func (a strAddr) Network() string { return "tcp" }
func (a strAddr) String() string  { return string(a) }
