package node

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

func selfSigned(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// The node's pin store never pins by itself: the first key is remembered and
// refused - before the device certificate is sent -, and only Accept pins.
func TestFilePinNeedsAcceptance(t *testing.T) {
	server, device := selfSigned(t, "control"), selfSigned(t, "device")
	sawClientCert := make(chan bool, 8)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAnyClientCert})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := c.(*tls.Conn)
			err = tc.Handshake()
			sawClientCert <- err == nil && len(tc.ConnectionState().PeerCertificates) > 0
			c.Close()
		}
	}()
	path := filepath.Join(t.TempDir(), "control.pin")
	pins := &filePin{path: path}
	dial := func() error {
		c, err := tls.Dial("tcp", ln.Addr().String(), transport.ClientTLSConfigControl(device, "nodes.test", pins, nil))
		if err == nil {
			// TLS 1.3: the server's verdict on our certificate arrives with the first read
			c.SetDeadline(time.Now().Add(2 * time.Second))
			c.Read(make([]byte, 1))
			c.Close()
		}
		return err
	}

	if err := dial(); err == nil {
		t.Fatal("connected to a control plane nobody accepted")
	}
	if <-sawClientCert {
		t.Fatal("the device certificate went to an unaccepted control plane")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("pinned on first use")
	}
	want, _ := devicekey.HashPublicKey(server.PrivateKey.(*ecdsa.PrivateKey).Public())
	seen, ok := pins.Seen()
	if !ok || seen != want {
		t.Fatalf("seen %v %v, want %v", seen, ok, want)
	}

	// accepting some other key: the real control plane is refused
	other, _ := devicekey.HashPublicKey(device.PrivateKey.(*ecdsa.PrivateKey).Public())
	if err := pins.Accept(other); err != nil {
		t.Fatal(err)
	}
	if err := dial(); err == nil {
		t.Fatal("connected although another key was accepted")
	}
	<-sawClientCert

	if err := pins.Accept(want); err != nil {
		t.Fatal(err)
	}
	if err := dial(); err != nil {
		t.Fatalf("accepted key refused: %v", err)
	}
	if !<-sawClientCert {
		t.Fatal("no client certificate after acceptance")
	}
	if fi, _ := os.Stat(path); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("pin file: %v", fi)
	}
}
