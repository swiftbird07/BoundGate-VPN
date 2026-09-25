package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The TCP fallback: the same CONNECT-IP tunnel over TLS on TCP/443, for
// networks that block UDP. RFC 9484 §4 for HTTP/1.1: the client asks for
// an upgrade to connect-ip, the server answers 101, and from then on the
// stream carries capsules (capsule.go). mTLS and the pinned keys are exactly
// those of the QUIC path; only the bytes below TLS differ. A mux or an
// SNI-passthrough reverse proxy in front sees an ordinary TLS connection
// for hub.boundgate.

const (
	upgradeProto = "connect-ip"
	alpnTCP      = "http/1.1"
)

// tcpTLSConfig adapts a QUIC TLS configuration to the TCP listener or
// dialer: same certificates, same verification, HTTP/1.1 as ALPN.
func tcpTLSConfig(c *tls.Config) *tls.Config {
	t := c.Clone()
	t.NextProtos = []string{alpnTCP}
	return t
}

// serveTCP accepts upgrade requests on ln until it is closed.
func (s *Server) serveTCP(ln net.Listener) error {
	path, err := templatePath(s.cfg.Template)
	if err != nil {
		return err
	}
	hs := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.handleTCP(w, r, path) }),
		ReadHeaderTimeout: 10 * time.Second,
		// a connection that sent its request is hijacked and lives by the
		// tunnel's own idle timeout; this one only ends idle connections
		// between requests, which an approved peer could otherwise hold
		// open forever
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: 16 << 10,
		ErrorLog:       nil,
	}
	s.mu.Lock()
	s.hs = hs
	s.mu.Unlock()
	return hs.Serve(tls.NewListener(ln, tcpTLSConfig(s.cfg.TLS)))
}

// handleTCP is the HTTP/1.1 counterpart of handle: authenticate the peer
// from the TLS state, check the upgrade, hand the hijacked stream to a
// capsule link and run the handler on it.
func (s *Server) handleTCP(w http.ResponseWriter, r *http.Request, path string) {
	if r.TLS == nil {
		http.Error(w, "tls required", http.StatusBadRequest)
		return
	}
	src := addrPortOf(strAddr(r.RemoteAddr)).Addr()
	peer, err := PeerFromTLSState(r.TLS, s.cfg.Lookup, src)
	if err != nil {
		s.log.Warn("transport: peer rejected after handshake", "src", src, "err", err, "transport", "tcp")
		http.Error(w, "device not approved", http.StatusForbidden)
		return
	}
	if strings.HasPrefix(r.URL.Path, relayPathPrefix) {
		s.handleRelayTCP(w, r, peer)
		return
	}
	if r.Method != http.MethodGet || r.URL.Path != path ||
		!strings.EqualFold(r.Header.Get("Upgrade"), upgradeProto) ||
		!headerHasToken(r.Header.Get("Connection"), "upgrade") ||
		r.Header.Get("Capsule-Protocol") != "?1" {
		s.log.Warn("transport: bad CONNECT-IP upgrade request", "peer", peer, "method", r.Method, "path", r.URL.Path)
		http.Error(w, "expected an upgrade to connect-ip", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cfg, status, err := s.h.Accept(r.Context(), peer)
	if err != nil || status != http.StatusOK {
		if status == 0 || status == http.StatusOK {
			status = http.StatusInternalServerError
		}
		s.log.Info("transport: tunnel refused", "peer", peer, "status", status, "err", err, "transport", "tcp")
		w.WriteHeader(status)
		return
	}
	defer s.h.Release(peer, cfg)
	conn, rw, err := hj.Hijack()
	if err != nil {
		s.log.Error("transport: hijack failed", "peer", peer, "err", err)
		return
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	head := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + upgradeProto + "\r\nCapsule-Protocol: ?1\r\n"
	if len(cfg.DNS) > 0 {
		head += DNSHeader + ": " + dnsHeader(cfg.DNS) + "\r\n"
	}
	if _, err := rw.WriteString(head + "\r\n"); err != nil || rw.Flush() != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	link := newCapsuleLink(conn, rw.Reader, s.cfg.IdleTimeout, s.cfg.KeepAlive)
	t := &Tunnel{id: newTunnelID(), peer: peer, cfg: cfg, link: link, transport: "tcp", opened: time.Now()}
	defer link.Close(0, "handler returned")
	if len(cfg.Assigned) > 0 {
		if err := link.AssignAddresses(cfg.Assigned); err != nil {
			s.log.Error("transport: assign addresses", "tunnel", t.id, "err", err)
			return
		}
	}
	if len(cfg.Routes) > 0 {
		if err := link.AdvertiseRoute(cfg.Routes); err != nil {
			s.log.Error("transport: advertise routes", "tunnel", t.id, "err", err)
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-link.Done()
		cancel()
	}()
	s.track(t)
	defer s.untrack(t)
	s.log.Info("transport: tunnel open", "tunnel", t.id, "peer", peer, "assigned", cfg.Assigned, "transport", "tcp")
	s.h.Serve(ctx, t)
	s.log.Info("transport: tunnel closed", "tunnel", t.id, "peer", peer, "duration", time.Since(t.opened).Round(time.Millisecond).String(), "transport", "tcp")
}

// DialTCP opens a tunnel over TCP: TLS with the same pinned configuration
// as Dial, then the CONNECT-IP upgrade. Refusals surface as DialError with
// the HTTP status, like on QUIC.
func DialTCP(ctx context.Context, cfg ClientConfig) (*ClientTunnel, error) {
	if cfg.TLS == nil || len(cfg.TLS.Certificates) == 0 {
		return nil, errors.New("transport: ClientConfig.TLS must come from ClientTLSConfig")
	}
	path, err := templatePath(cfg.Template)
	if err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: cfg.HandshakeTimeout, KeepAlive: cfg.KeepAlive}, Config: tcpTLSConfig(cfg.TLS)}
	hctx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()
	raw, err := d.DialContext(hctx, "tcp", cfg.GatewayAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: dial tcp %s: %w", cfg.GatewayAddr, err)
	}
	conn := raw.(*tls.Conn)
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: cfg.TLS.ServerName, Path: path},
		Host:   cfg.TLS.ServerName,
		Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {upgradeProto}, "Capsule-Protocol": {"?1"}},
	}
	_ = conn.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("transport: upgrade request: %w", err)
	}
	r := bufio.NewReaderSize(conn, 64<<10)
	rsp, err := http.ReadResponse(r, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("transport: upgrade response: %w", err)
	}
	if rsp.StatusCode != http.StatusSwitchingProtocols {
		_ = rsp.Body.Close()
		_ = conn.Close()
		return nil, &DialError{Status: rsp.StatusCode, Err: fmt.Errorf("HTTP %s", rsp.Status)}
	}
	if !strings.EqualFold(rsp.Header.Get("Upgrade"), upgradeProto) {
		_ = conn.Close()
		return nil, &DialError{Status: rsp.StatusCode, Err: errors.New("101 without the connect-ip upgrade")}
	}
	_ = conn.SetDeadline(time.Time{})
	return &ClientTunnel{link: newCapsuleLink(conn, r, cfg.IdleTimeout, cfg.KeepAlive), transport: "tcp", cfg: cfg, dns: parseDNSHeader(rsp.Header.Get(DNSHeader))}, nil
}

// templatePath is the request target for a CONNECT-IP template without
// variables, e.g. "/vpn" for HubTemplate.
func templatePath(tmpl string) (string, error) {
	u, err := url.Parse(tmpl)
	if err != nil || u.Path == "" || strings.Contains(u.Path, "{") {
		return "", fmt.Errorf("transport: template %q has no fixed path", tmpl)
	}
	return u.Path, nil
}

func headerHasToken(v, token string) bool {
	for _, f := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(f), token) {
			return true
		}
	}
	return false
}

type strAddr string

func (a strAddr) Network() string { return "tcp" }
func (a strAddr) String() string  { return string(a) }
