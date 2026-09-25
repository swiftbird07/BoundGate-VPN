package transport_test

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// A resumed handshake proves the ticket, not the device key. The servers
// must therefore never resume: a client that keeps a ticket (a copy taken
// off an enrolled device, a device revoked since) gets a full handshake and
// the key check every time.
func TestServersNeverResumeASession(t *testing.T) {
	serverCert, _ := newServerCert(t)
	device, spki := newDevice(t, "dev-a")
	lookup := &staticLookup{m: map[devicekey.SPKIHash]transport.DeviceInfo{spki: {ID: "dev-a"}}}

	for name, cfg := range map[string]*tls.Config{
		"approved devices": transport.ServerTLSConfig(serverCert, lookup),
		"enrollment":       transport.ServerTLSConfigAnyDevice(serverCert),
	} {
		t.Run(name, func(t *testing.T) {
			verified := 0
			check := cfg.VerifyPeerCertificate
			cfg.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
				verified++
				return check(raw, chains)
			}
			cfg.NextProtos = nil
			// a client that asks for tickets, unlike ours
			client := &tls.Config{
				Certificates:       []tls.Certificate{device},
				InsecureSkipVerify: true,
				ClientSessionCache: tls.NewLRUClientSessionCache(4),
				ServerName:         "gateway.test",
			}
			for i := range 2 {
				if resumed := handshake(t, cfg, client); resumed {
					t.Fatalf("handshake %d resumed a session", i+1)
				}
			}
			if verified != 2 {
				t.Fatalf("the device key was checked %d times in 2 handshakes", verified)
			}
		})
	}
}

// handshake connects once over loopback TCP, lets the client read what the
// server sends after the handshake (where TLS 1.3 tickets arrive) and
// reports whether the session was resumed.
func handshake(t *testing.T, server, client *tls.Config) bool {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		if err := c.(*tls.Conn).Handshake(); err != nil {
			done <- err
			return
		}
		_, err = c.Write([]byte{1})
		done <- err
	}()
	c, err := tls.Dial("tcp", ln.Addr().String(), client)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return c.ConnectionState().DidResume
}
