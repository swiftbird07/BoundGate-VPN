package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// ClientConfig configures the agent side of a tunnel.
type ClientConfig struct {
	// GatewayAddr is host:port of the gateway's UDP listener.
	GatewayAddr string
	// TLS must come from ClientTLSConfig.
	TLS *tls.Config
	// Template is the gateway's CONNECT-IP URI template.
	Template    string
	IdleTimeout time.Duration
	KeepAlive   time.Duration
	// HandshakeTimeout bounds the QUIC or TLS handshake. Default 5s: on a
	// network that blacks out UDP this is how long the QUIC attempt takes
	// before the caller falls back to TCP.
	HandshakeTimeout time.Duration
}

func (c ClientConfig) withDefaults() ClientConfig {
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 60 * time.Second
	}
	if c.KeepAlive == 0 {
		c.KeepAlive = 20 * time.Second
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 5 * time.Second
	}
	return c
}

// clientLink is what a ClientTunnel needs from its transport.
type clientLink interface {
	ReadPacket(b []byte) (int, error)
	WritePacket(b []byte) (icmp []byte, err error)
	LocalPrefixes(ctx context.Context) ([]netip.Prefix, error)
	Routes(ctx context.Context) ([]connectip.IPRoute, error)
	Done() <-chan struct{}
	Err() error
	Close(code quic.ApplicationErrorCode, reason string) error
}

// quicClientLink adapts connect-ip-go's client session to clientLink.
type quicClientLink struct {
	conn  *connectip.Conn
	qconn *quic.Conn
	cc    *http3.ClientConn
	tr    *http3.Transport
}

func (l *quicClientLink) ReadPacket(b []byte) (int, error)     { return l.conn.ReadPacket(b) }
func (l *quicClientLink) WritePacket(b []byte) ([]byte, error) { return l.conn.WritePacket(b) }
func (l *quicClientLink) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	return l.conn.LocalPrefixes(ctx)
}
func (l *quicClientLink) Routes(ctx context.Context) ([]connectip.IPRoute, error) {
	return l.conn.Routes(ctx)
}
func (l *quicClientLink) Done() <-chan struct{} { return l.qconn.Context().Done() }
func (l *quicClientLink) Err() error {
	select {
	case <-l.qconn.Context().Done():
		return context.Cause(l.qconn.Context())
	default:
		return nil
	}
}
func (l *quicClientLink) Close(code quic.ApplicationErrorCode, reason string) error {
	_ = l.conn.Close()
	err := l.qconn.CloseWithError(code, reason)
	_ = l.tr.Close()
	return err
}

// ClientTunnel is the agent's end of an accepted tunnel.
type ClientTunnel struct {
	link      clientLink
	transport string // "quic" or "tcp"
}

// Dial performs the QUIC/mTLS handshake and the CONNECT-IP request. Any
// failure in the handshake (including "device not approved") surfaces here.
func Dial(ctx context.Context, cfg ClientConfig) (*ClientTunnel, error) {
	if cfg.TLS == nil || len(cfg.TLS.Certificates) == 0 {
		return nil, errors.New("transport: ClientConfig.TLS must come from ClientTLSConfig")
	}
	tmpl, err := uritemplate.New(cfg.Template)
	if err != nil {
		return nil, fmt.Errorf("transport: template: %w", err)
	}
	cfg = cfg.withDefaults()
	qconn, err := quic.DialAddr(ctx, cfg.GatewayAddr, cfg.TLS, &quic.Config{
		EnableDatagrams:      true,
		MaxIdleTimeout:       cfg.IdleTimeout,
		KeepAlivePeriod:      cfg.KeepAlive,
		HandshakeIdleTimeout: cfg.HandshakeTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s: %w", cfg.GatewayAddr, err)
	}
	tr := &http3.Transport{EnableDatagrams: true}
	cc := tr.NewClientConn(qconn)
	conn, rsp, err := connectip.Dial(ctx, cc, tmpl)
	if err != nil {
		status := 0
		if rsp != nil {
			status = rsp.StatusCode
		}
		_ = qconn.CloseWithError(0, "connect-ip failed")
		return nil, &DialError{Status: status, Err: err}
	}
	return &ClientTunnel{link: &quicClientLink{conn: conn, qconn: qconn, cc: cc, tr: tr}, transport: "quic"}, nil
}

// DialError reports a CONNECT-IP refusal. Status is the HTTP status if the
// gateway answered (403 = no session), 0 otherwise.
type DialError struct {
	Status int
	Err    error
}

func (e *DialError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("transport: gateway refused tunnel with HTTP %d: %v", e.Status, e.Err)
	}
	return "transport: " + e.Err.Error()
}

func (e *DialError) Unwrap() error { return e.Err }

// Transport is "quic" or "tcp".
func (t *ClientTunnel) Transport() string { return t.transport }

// ReadPacket reads one IP packet from the gateway.
func (t *ClientTunnel) ReadPacket(b []byte) (int, error) { return t.link.ReadPacket(b) }

// WritePacket sends one IP packet to the gateway.
func (t *ClientTunnel) WritePacket(b []byte) (icmp []byte, err error) { return t.link.WritePacket(b) }

// LocalPrefixes returns the addresses the gateway assigned.
func (t *ClientTunnel) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	return t.link.LocalPrefixes(ctx)
}

// Routes returns the routes the gateway advertised.
func (t *ClientTunnel) Routes(ctx context.Context) ([]connectip.IPRoute, error) {
	return t.link.Routes(ctx)
}

// Done is closed when the connection ends; Err then explains why.
func (t *ClientTunnel) Done() <-chan struct{} { return t.link.Done() }

// Err returns the reason the connection ended, or nil while it is alive.
func (t *ClientTunnel) Err() error { return t.link.Err() }

// Close ends the tunnel cleanly.
func (t *ClientTunnel) Close() error { return t.link.Close(0, "client closed") }
