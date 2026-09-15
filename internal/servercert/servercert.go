// Package servercert creates and loads the gateway's (and control plane's)
// TLS server certificate. In the prototype it is self-signed; agents pin it
// by loading the PEM as their only trusted root. Later this can come from
// the control plane's CA or ACME.
package servercert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// LoadOrCreate returns the certificate at certPath/keyPath, creating a
// self-signed one for the given names when the files do not exist.
func LoadOrCreate(certPath, keyPath string, names []string) (tls.Certificate, bool, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		if cert.Leaf == nil {
			cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		}
		return cert, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, false, fmt.Errorf("servercert: load: %w", err)
	}
	cert, err = create(certPath, keyPath, names)
	return cert, true, err
}

func create(certPath, keyPath string, names []string) (tls.Certificate, error) {
	if len(names) == 0 {
		return tls.Certificate{}, errors.New("servercert: at least one name is required")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: names[0], Organization: []string{"BoundGate"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, n := range names {
		if ip, err := netip.ParseAddr(n); err == nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(ip.AsSlice()))
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	for _, p := range []string{certPath, keyPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return tls.Certificate{}, err
		}
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
}

// LoadRoots reads one or more PEM certificates into a pool.
func LoadRoots(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("servercert: no certificates in %s", path)
	}
	return pool, nil
}
