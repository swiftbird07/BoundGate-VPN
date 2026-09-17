package tpm2key

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicecert"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
)

// These tests need a TPM: BOUNDGATE_TEST_TPM=tcp:HOST:PORT (or unix:PATH, or
// a device). `make test-tpm` starts a software TPM and sets it.
func testDevice(t *testing.T) string {
	dev := os.Getenv("BOUNDGATE_TEST_TPM")
	if dev == "" {
		t.Skip("BOUNDGATE_TEST_TPM not set (make test-tpm)")
	}
	return dev
}

func openKey(t *testing.T, dev, path string) *Key {
	t.Helper()
	k, err := New(dev, path).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.(*Key).Close() })
	return k.(*Key)
}

func TestCreateReopenSign(t *testing.T) {
	dev := testDevice(t)
	path := filepath.Join(t.TempDir(), "device.tpm")
	k := openKey(t, dev, path)
	if !k.HardwareBound() || k.Kind() != "tpm2" {
		t.Fatalf("hardware_bound=%v kind=%s", k.HardwareBound(), k.Kind())
	}
	if err := devicekey.CheckPublicKey(k.Public()); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	digest := sha256.Sum256([]byte("boundgate"))
	for i := 0; i < 3; i++ {
		sig, err := k.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(k.Public().(*ecdsa.PublicKey), digest[:], sig) {
			t.Fatal("signature does not verify")
		}
	}
	if _, err := k.Sign(rand.Reader, digest[:], crypto.SHA384); err == nil {
		t.Fatal("SHA-384 accepted")
	}
	if _, err := k.Sign(rand.Reader, digest[:8], crypto.SHA256); err == nil {
		t.Fatal("short digest accepted")
	}
	want, _ := devicekey.HashPublicKey(k.Public())
	k.Close()
	if _, err := k.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("closed key signed")
	}

	// the same file yields the same identity; a process that died without
	// Close (no flush) must not exhaust the TPM
	for i := 0; i < 6; i++ {
		tpm, raw, err := openTPM(dev)
		if err != nil {
			t.Fatal(err)
		}
		again, err := open(tpm, raw, path)
		if err != nil {
			t.Fatalf("reopen %d: %v", i, err)
		}
		got, _ := devicekey.HashPublicKey(again.Public())
		if got != want {
			t.Fatal("reopened key has another public key")
		}
		tpm.Close() // leaks the loaded object, like a crash
	}
}

func TestForeignOrDamagedBlobDoesNotLoad(t *testing.T) {
	dev := testDevice(t)
	path := filepath.Join(t.TempDir(), "device.tpm")
	openKey(t, dev, path).Close()
	b, _ := os.ReadFile(path)
	var blob blobFile
	if err := json.Unmarshal(b, &blob); err != nil {
		t.Fatal(err)
	}
	blob.Private[len(blob.Private)-1] ^= 1 // what a blob wrapped by another TPM looks like to this one
	if err := writeBlob(path, blob); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dev, path).Open(context.Background()); err == nil {
		t.Fatal("damaged blob loaded")
	}
}

// The key must work where it is used: a self-signed device certificate and
// TLS 1.3 client authentication.
func TestTLSClientAuth(t *testing.T) {
	dev := testDevice(t)
	dir := t.TempDir()
	k := openKey(t, dev, filepath.Join(dir, "device.tpm"))
	cert, err := devicecert.LoadOrCreate(filepath.Join(dir, "device.crt"), k, "tpm-test")
	if err != nil {
		t.Fatal(err)
	}
	srvKey, _ := ecdsa.GenerateKey(k.Public().(*ecdsa.PublicKey).Curve, rand.Reader)
	_ = srvKey
	srvCert, err := devicecert.LoadOrCreate(filepath.Join(dir, "server.crt"), softSigner{srvKey}, "server")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan devicekey.SPKIHash, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			seen <- devicekey.SPKIHash{}
			return
		}
		h, _ := devicekey.HashPublicKey(tc.ConnectionState().PeerCertificates[0].PublicKey)
		seen <- h
		c.Write([]byte("ok"))
	}()
	c, err := tls.DialWithDialer(&net.Dialer{}, "tcp", ln.Addr().String(), &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 2)
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}
	want, _ := devicekey.HashPublicKey(k.Public())
	if got := <-seen; got != want {
		t.Fatalf("server saw %s, want %s", got, want)
	}
}

type softSigner struct{ *ecdsa.PrivateKey }

func (softSigner) HardwareBound() bool { return false }
func (softSigner) Kind() string        { return "test" }
