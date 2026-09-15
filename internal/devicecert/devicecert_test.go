package devicecert_test

import (
	"context"
	"crypto/x509"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicecert"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey/softkey"
)

func TestSelfSignedProperties(t *testing.T) {
	dir := t.TempDir()
	key, err := softkey.New(filepath.Join(dir, "key")).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := devicecert.SelfSigned(key, "laptop-1")
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf
	if leaf.Subject.CommonName != "laptop-1" {
		t.Fatalf("CN %q", leaf.Subject.CommonName)
	}
	if leaf.NotAfter.Year() != 9999 {
		t.Fatalf("NotAfter %v, want maximal lifetime", leaf.NotAfter)
	}
	if leaf.IsCA {
		t.Fatal("device cert must not be a CA")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("ExtKeyUsage %v", leaf.ExtKeyUsage)
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatalf("self-signature: %v", err)
	}
	h, _ := devicekey.HashPublicKey(key.Public())
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "boundgate:device:"+h.String() {
		t.Fatalf("URIs %v", leaf.URIs)
	}
	if time.Now().Before(leaf.NotBefore) {
		t.Fatal("cert not yet valid")
	}
}

func TestLoadOrCreateAndKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	key, _ := softkey.New(filepath.Join(dir, "key")).Open(context.Background())
	certPath := filepath.Join(dir, "cert.pem")

	c1, err := devicecert.LoadOrCreate(certPath, key, "x")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := devicecert.LoadOrCreate(certPath, key, "x")
	if err != nil {
		t.Fatal(err)
	}
	if string(c1.Certificate[0]) != string(c2.Certificate[0]) {
		t.Fatal("second LoadOrCreate created a new certificate")
	}

	other, _ := softkey.New(filepath.Join(dir, "other")).Open(context.Background())
	if _, err := devicecert.Load(certPath, other); !errors.Is(err, devicecert.ErrKeyMismatch) {
		t.Fatalf("want ErrKeyMismatch, got %v", err)
	}
	c3, err := devicecert.LoadOrCreate(certPath, other, "y")
	if err != nil {
		t.Fatal(err)
	}
	if string(c3.Certificate[0]) == string(c1.Certificate[0]) {
		t.Fatal("mismatching cert was not replaced")
	}
}
