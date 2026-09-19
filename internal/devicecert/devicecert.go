// Package devicecert turns a DeviceKey into the self-signed X.509 certificate
// that TLS needs as a carrier for the public key.
//
// There is deliberately no CA. Trust is established by looking up the SPKI
// hash of the presented key in the device registry, not by chain validation.
// The certificate therefore has the maximum lifetime; revocation happens by
// removing the key from the registry (see docs/SECURITY.md).
//
// This package is part of the security TCB (see docs/TCB.md).
package devicecert

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
)

// URIScheme is the SAN URI scheme carrying the SPKI hash, e.g.
// boundgate:device:<hex>. It is informational; verifiers recompute the hash
// from the key and never trust the SAN.
const URIScheme = "boundgate"

// maxNotAfter is the largest time RFC 5280 can encode (GeneralizedTime).
var maxNotAfter = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// SelfSigned creates a self-signed client certificate for the device key.
// deviceName is used as the CN and is purely cosmetic.
func SelfSigned(key devicekey.DeviceKey, deviceName string) (tls.Certificate, error) {
	if err := devicekey.CheckPublicKey(key.Public()); err != nil {
		return tls.Certificate{}, err
	}
	spki, err := devicekey.HashPublicKey(key.Public())
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("devicecert: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: deviceName, Organization: []string{"BoundGate device"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              maxNotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{{Scheme: URIScheme, Opaque: "device:" + spki.String()}},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("devicecert: create: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("devicecert: parse: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// Save writes the certificate DER as PEM (0644; it contains no secret).
func Save(path string, cert tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return errors.New("devicecert: empty certificate")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads a saved certificate and pairs it with the device key. It fails
// if the certificate's public key does not match the key, which happens when
// the key store was recreated; the caller should then create a new cert.
func Load(path string, key devicekey.DeviceKey) (tls.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return tls.Certificate{}, errors.New("devicecert: not a CERTIFICATE PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("devicecert: parse: %w", err)
	}
	want, err := devicekey.HashPublicKey(key.Public())
	if err != nil {
		return tls.Certificate{}, err
	}
	got, err := devicekey.HashPublicKey(leaf.PublicKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	if got != want {
		return tls.Certificate{}, ErrKeyMismatch
	}
	return tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key, Leaf: leaf}, nil
}

// ErrKeyMismatch is returned by Load when the certificate belongs to a
// different key than the one provided.
var ErrKeyMismatch = errors.New("devicecert: certificate does not match device key")

// LoadOrCreate loads the certificate at path or creates and saves a new one.
func LoadOrCreate(path string, key devicekey.DeviceKey, deviceName string) (tls.Certificate, error) {
	cert, err := Load(path, key)
	if err == nil {
		return cert, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, ErrKeyMismatch) {
		return tls.Certificate{}, err
	}
	cert, err = SelfSigned(key, deviceName)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := Save(path, cert); err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}
