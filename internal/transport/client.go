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
}

// ClientTunnel is the agent's end of an accepted tunnel.
type ClientTunnel struct {
	conn  *connectip.Conn
	qconn *quic.Conn
	cc    *http3.ClientConn
	tr    *http3.Transport
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
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	if cfg.KeepAlive == 0 {
		cfg.KeepAlive = 20 * time.Second
	}
	qconn, err := quic.DialAddr(ctx, cfg.GatewayAddr, cfg.TLS, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  cfg.IdleTimeout,
		KeepAlivePeriod: cfg.KeepAlive,
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
	return &ClientTunnel{conn: conn, qconn: qconn, cc: cc, tr: tr}, nil
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

// ReadPacket reads one IP packet from the gateway.
func (t *ClientTunnel) ReadPacket(b []byte) (int, error) { return t.conn.ReadPacket(b) }

// WritePacket sends one IP packet to the gateway.
func (t *ClientTunnel) WritePacket(b []byte) (icmp []byte, err error) { return t.conn.WritePacket(b) }

// LocalPrefixes returns the addresses the gateway assigned.
func (t *ClientTunnel) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	return t.conn.LocalPrefixes(ctx)
}

// Routes returns the routes the gateway advertised.
func (t *ClientTunnel) Routes(ctx context.Context) ([]connectip.IPRoute, error) {
	return t.conn.Routes(ctx)
}

// Done is closed when the QUIC connection ends; Err then explains why.
func (t *ClientTunnel) Done() <-chan struct{} { return t.qconn.Context().Done() }

// Err returns the reason the connection ended, or nil while it is alive.
func (t *ClientTunnel) Err() error {
	select {
	case <-t.qconn.Context().Done():
		return context.Cause(t.qconn.Context())
	default:
		return nil
	}
}

// Close ends the tunnel cleanly.
func (t *ClientTunnel) Close() error {
	_ = t.conn.Close()
	err := t.qconn.CloseWithError(0, "client closed")
	_ = t.tr.Close()
	return err
}
