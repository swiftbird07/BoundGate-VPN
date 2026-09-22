package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// TunnelConfig is what the gateway grants a peer when accepting a tunnel.
type TunnelConfig struct {
	// Assigned prefixes become the peer's VPN addresses (ADDRESS_ASSIGN).
	Assigned []netip.Prefix
	// Routes are advertised to the peer (ROUTE_ADVERTISEMENT). The peer may
	// route less, never more.
	Routes []connectip.IPRoute
}

// Handler is implemented by the gateway service. Both methods run with an
// AuthenticatedPeer that this package produced; nothing else can call them.
type Handler interface {
	// Accept decides whether the peer gets a tunnel. Return an HTTP status
	// other than 200 to reject (403 no session, 503 no addresses, ...).
	Accept(ctx context.Context, peer AuthenticatedPeer) (TunnelConfig, int, error)
	// Serve moves packets until the tunnel ends. It must return when ctx is
	// done or ReadPacket fails.
	Serve(ctx context.Context, t *Tunnel)
	// Release is called exactly once for every successful Accept, after
	// Serve returned or when tunnel setup failed before Serve. Handlers free
	// the resources granted in Accept (the VPN address) here.
	Release(peer AuthenticatedPeer, cfg TunnelConfig)
}

// serverLink is what a Tunnel needs from its transport: the QUIC
// connection with its CONNECT-IP session, or the capsule stream on TCP.
type serverLink interface {
	ReadPacket(b []byte) (int, error)
	WritePacket(b []byte) (icmp []byte, err error)
	Done() <-chan struct{}
	Err() error
	Close(code quic.ApplicationErrorCode, reason string) error
}

// quicLink adapts connect-ip-go's session to serverLink.
type quicLink struct {
	conn  *connectip.Conn
	qconn *quic.Conn
}

func (l *quicLink) ReadPacket(b []byte) (int, error) { return l.conn.ReadPacket(b) }
func (l *quicLink) WritePacket(b []byte) ([]byte, error) {
	icmp, err := l.conn.WritePacket(b)
	return tooLarge(b, icmp), err
}
func (l *quicLink) Done() <-chan struct{} { return l.qconn.Context().Done() }
func (l *quicLink) Close(c quic.ApplicationErrorCode, r string) error {
	return l.qconn.CloseWithError(c, r)
}
func (l *quicLink) Err() error {
	select {
	case <-l.qconn.Context().Done():
		return context.Cause(l.qconn.Context())
	default:
		return nil
	}
}

// Tunnel is one accepted CONNECT-IP session with an authenticated peer.
type Tunnel struct {
	id        string
	peer      AuthenticatedPeer
	cfg       TunnelConfig
	link      serverLink
	transport string // "quic" or "tcp"
	opened    time.Time
	once      sync.Once

	mu        sync.Mutex
	localCode quic.ApplicationErrorCode
	localWhy  string
	localSet  bool
}

// ID is a random per-tunnel identifier for logs.
func (t *Tunnel) ID() string { return t.id }

// Peer returns the authenticated device.
func (t *Tunnel) Peer() AuthenticatedPeer { return t.peer }

// Config returns what was granted at Accept.
func (t *Tunnel) Config() TunnelConfig { return t.cfg }

// Opened is when the tunnel was accepted.
func (t *Tunnel) Opened() time.Time { return t.opened }

// Transport is "quic" or "tcp".
func (t *Tunnel) Transport() string { return t.transport }

// ReadPacket reads one IP packet sent by the device.
func (t *Tunnel) ReadPacket(b []byte) (int, error) { return t.link.ReadPacket(b) }

// WritePacket sends one IP packet to the device. A non-nil icmp return is an
// ICMP error the caller should deliver back towards the original sender.
func (t *Tunnel) WritePacket(b []byte) (icmp []byte, err error) { return t.link.WritePacket(b) }

// Done is closed when the underlying connection ends.
func (t *Tunnel) Done() <-chan struct{} { return t.link.Done() }

// Err returns why the connection ended, or nil while it is alive.
func (t *Tunnel) Err() error { return t.link.Err() }

// Close ends the tunnel with an application error code.
func (t *Tunnel) Close(code quic.ApplicationErrorCode, reason string) error {
	var err error
	t.once.Do(func() {
		t.mu.Lock()
		t.localCode, t.localWhy, t.localSet = code, reason, true
		t.mu.Unlock()
		err = t.link.Close(code, reason)
	})
	return err
}

// LocalClose reports the code and reason this side closed the tunnel with,
// if it did.
func (t *Tunnel) LocalClose() (quic.ApplicationErrorCode, string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.localCode, t.localWhy, t.localSet
}

// ServerConfig configures a gateway listener.
type ServerConfig struct {
	// Addr is the UDP listen address, e.g. ":443".
	Addr string
	// TLS must come from ServerTLSConfig.
	TLS *tls.Config
	// Lookup is the same registry the TLS config uses.
	Lookup DeviceLookup
	// Template is the CONNECT-IP URI template, e.g. "https://gw.example/vpn".
	Template string
	// IdleTimeout closes tunnels without any QUIC activity. Default 60s.
	IdleTimeout time.Duration
	// KeepAlive sends QUIC PINGs to keep NAT bindings alive. Default 20s.
	KeepAlive time.Duration
	Logger    *slog.Logger
	// PacketConn, when set, is used instead of binding Addr, and
	// ConnIDGenerator shapes the connection IDs this server issues. Both
	// exist for servers that share a public port behind a front
	// (internal/mux); neither touches authentication.
	PacketConn      net.PacketConn
	ConnIDGenerator quic.ConnectionIDGenerator
	// TCPListener, when set, also serves the tunnel over TCP (tcp.go): the
	// fallback for clients whose network blocks UDP. Same TLS, same peers.
	TCPListener net.Listener
	// Relayed: PacketConn is a relay stream of a hub connection
	// (ClientTunnel.RelayListen). The QUIC connections on it stay at the
	// minimum packet size and do not probe for more: the carrier's datagrams
	// are not certain to hold larger ones. Tunnels report transport "relay".
	Relayed bool
}

// Server terminates QUIC + mTLS + CONNECT-IP for approved devices.
type Server struct {
	cfg     ServerConfig
	h       Handler
	tmpl    *uritemplate.Template
	log     *slog.Logger
	h3      *http3.Server
	hs      *http.Server
	pconn   net.PacketConn
	qt      *quic.Transport
	mu      sync.Mutex
	tunnels map[DeviceID]map[*Tunnel]struct{}
	relay   relay
}

type quicConnKey struct{}

// NewServer validates the configuration and prepares the listener.
func NewServer(cfg ServerConfig, h Handler) (*Server, error) {
	if cfg.TLS == nil || cfg.TLS.ClientAuth != tls.RequireAnyClientCert || cfg.TLS.VerifyPeerCertificate == nil {
		return nil, errors.New("transport: ServerConfig.TLS must come from ServerTLSConfig")
	}
	if cfg.Lookup == nil {
		return nil, errors.New("transport: ServerConfig.Lookup is required")
	}
	if h == nil {
		return nil, errors.New("transport: Handler is required")
	}
	tmpl, err := uritemplate.New(cfg.Template)
	if err != nil {
		return nil, fmt.Errorf("transport: template: %w", err)
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	if cfg.KeepAlive == 0 {
		cfg.KeepAlive = 20 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{
		cfg:     cfg,
		h:       h,
		tmpl:    tmpl,
		log:     cfg.Logger,
		tunnels: make(map[DeviceID]map[*Tunnel]struct{}),
	}
	s.relay.listeners = make(map[netip.Addr]*relayListener)
	s.h3 = &http3.Server{
		TLSConfig:       cfg.TLS,
		Handler:         http.HandlerFunc(s.handle),
		EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams: true,
			Allow0RTT:       false,
			MaxIdleTimeout:  cfg.IdleTimeout,
			KeepAlivePeriod: cfg.KeepAlive,
			// PacketSize, not quic-go's 1280, also behind a mux (mtu.go)
			InitialPacketSize: PacketSize,
		},
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			return context.WithValue(ctx, quicConnKey{}, c)
		},
		Logger: cfg.Logger,
	}
	if cfg.Relayed {
		s.h3.QUICConfig.InitialPacketSize = 1200
		s.h3.QUICConfig.DisablePathMTUDiscovery = true
	}
	return s, nil
}

// Listen binds the UDP socket. It is separate from Serve so callers can learn
// the bound address (tests use port 0).
func (s *Server) Listen() error {
	if s.cfg.PacketConn != nil {
		s.pconn = s.cfg.PacketConn
		return nil
	}
	pc, err := net.ListenPacket("udp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("transport: listen %s: %w", s.cfg.Addr, err)
	}
	s.pconn = pc
	return nil
}

// LocalAddr returns the bound address after Listen.
func (s *Server) LocalAddr() net.Addr {
	if s.pconn == nil {
		return nil
	}
	return s.pconn.LocalAddr()
}

// Serve runs until ctx is done, then closes all tunnels with ErrCodeShutdown.
func (s *Server) Serve(ctx context.Context) error {
	if s.pconn == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	s.qt = &quic.Transport{Conn: s.pconn, ConnectionIDGenerator: s.cfg.ConnIDGenerator}
	ln, err := s.qt.ListenEarly(http3.ConfigureTLSConfig(s.cfg.TLS), s.h3.QUICConfig)
	if err != nil {
		return fmt.Errorf("transport: listen: %w", err)
	}
	errc := make(chan error, 2)
	go func() { errc <- s.h3.ServeListener(ln) }()
	if s.cfg.TCPListener != nil {
		go func() { errc <- s.serveTCP(s.cfg.TCPListener) }()
	}
	select {
	case <-ctx.Done():
		s.closeAll(ErrCodeShutdown, "hub shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.h3.Shutdown(shutdownCtx)
		_ = s.qt.Close()
		_ = s.pconn.Close()
		if s.cfg.TCPListener != nil {
			s.mu.Lock()
			hs := s.hs
			s.mu.Unlock()
			if hs != nil {
				_ = hs.Close()
			}
			_ = s.cfg.TCPListener.Close()
			<-errc
		}
		<-errc
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) transportName() string {
	if s.cfg.Relayed {
		return "relay"
	}
	return "quic"
}

// handle is the HTTP/3 handler for CONNECT-IP requests.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	qconn, _ := r.Context().Value(quicConnKey{}).(*quic.Conn)
	if qconn == nil {
		s.log.Error("transport: request without QUIC connection in context")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	src := addrPortOf(qconn.RemoteAddr()).Addr()
	st := qconn.ConnectionState().TLS
	peer, err := PeerFromTLSState(&st, s.cfg.Lookup, src)
	if err != nil {
		// The handshake already enforced membership; reaching this point means
		// the device was revoked in between. Close hard so the client knows.
		s.log.Warn("transport: peer rejected after handshake", "src", src, "err", err)
		w.WriteHeader(http.StatusForbidden)
		_ = qconn.CloseWithError(ErrCodeRevoked, "device not approved")
		return
	}
	if r.Method == http.MethodConnect && r.Proto == relayProtocol {
		s.handleRelay(w, r, peer)
		return
	}
	req, err := connectip.ParseRequest(r, s.tmpl)
	if err != nil {
		var perr *connectip.RequestParseError
		status := http.StatusBadRequest
		if errors.As(err, &perr) {
			status = perr.HTTPStatus
		}
		s.log.Warn("transport: bad CONNECT-IP request", "peer", peer, "err", err)
		w.WriteHeader(status)
		return
	}
	cfg, status, err := s.h.Accept(r.Context(), peer)
	if err != nil || status != http.StatusOK {
		if status == 0 || status == http.StatusOK {
			status = http.StatusInternalServerError
		}
		s.log.Info("transport: tunnel refused", "peer", peer, "status", status, "err", err)
		w.WriteHeader(status)
		return
	}
	defer s.h.Release(peer, cfg)
	p := &connectip.Proxy{}
	conn, err := p.Proxy(w, req)
	if err != nil {
		s.log.Error("transport: proxy setup failed", "peer", peer, "err", err)
		return
	}
	t := &Tunnel{id: newTunnelID(), peer: peer, cfg: cfg, link: &quicLink{conn: conn, qconn: qconn}, transport: s.transportName(), opened: time.Now()}
	defer conn.Close()
	if len(cfg.Assigned) > 0 {
		if err := conn.AssignAddresses(r.Context(), cfg.Assigned); err != nil {
			s.log.Error("transport: assign addresses", "tunnel", t.id, "err", err)
			return
		}
	}
	if len(cfg.Routes) > 0 {
		if err := conn.AdvertiseRoute(r.Context(), cfg.Routes); err != nil {
			s.log.Error("transport: advertise routes", "tunnel", t.id, "err", err)
			return
		}
	}
	s.track(t)
	defer s.untrack(t)
	s.log.Info("transport: tunnel open", "tunnel", t.id, "peer", peer, "assigned", cfg.Assigned)
	s.h.Serve(r.Context(), t)
	s.log.Info("transport: tunnel closed", "tunnel", t.id, "peer", peer, "duration", time.Since(t.opened).Round(time.Millisecond).String())
}

func (s *Server) track(t *Tunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.tunnels[t.peer.deviceID]
	if m == nil {
		m = make(map[*Tunnel]struct{})
		s.tunnels[t.peer.deviceID] = m
	}
	m[t] = struct{}{}
}

func (s *Server) untrack(t *Tunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m := s.tunnels[t.peer.deviceID]; m != nil {
		delete(m, t)
		if len(m) == 0 {
			delete(s.tunnels, t.peer.deviceID)
		}
	}
}

// CloseDevice terminates every tunnel of a device. It is the revocation path:
// the registry diff calls it when a device disappears from the snapshot.
func (s *Server) CloseDevice(id DeviceID, code quic.ApplicationErrorCode, reason string) int {
	s.mu.Lock()
	ts := make([]*Tunnel, 0, len(s.tunnels[id]))
	for t := range s.tunnels[id] {
		ts = append(ts, t)
	}
	s.mu.Unlock()
	for _, t := range ts {
		_ = t.Close(code, reason)
	}
	return len(ts)
}

// ActiveDevices lists devices with at least one open tunnel.
func (s *Server) ActiveDevices() []DeviceID {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]DeviceID, 0, len(s.tunnels))
	for id := range s.tunnels {
		ids = append(ids, id)
	}
	return ids
}

func (s *Server) closeAll(code quic.ApplicationErrorCode, reason string) {
	for _, id := range s.ActiveDevices() {
		s.CloseDevice(id, code, reason)
	}
}

func newTunnelID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func addrPortOf(a net.Addr) netip.AddrPort {
	if ua, ok := a.(*net.UDPAddr); ok {
		return ua.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}
