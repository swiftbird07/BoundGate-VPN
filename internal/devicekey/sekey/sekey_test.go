package sekey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The tests run everywhere, so the Secure Enclave is played by this test
// binary itself: copied to <dir>/boundgate-sekey it speaks the helper's
// protocol with a software key whose PKCS#8 form is the "blob". A file named
// "mode" next to it makes it misbehave. The real helper is tried on a Mac
// (docs/SECURE-ENCLAVE.md).
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == HelperName {
		os.Exit(fakeHelper(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeHelper(args []string) int {
	fail := func(msg string) int { fmt.Fprintln(os.Stderr, "boundgate-sekey: "+msg); return 1 }
	if len(os.Environ()) != 0 {
		return fail("the daemon's environment leaked into the helper")
	}
	mode, _ := os.ReadFile(filepath.Join(filepath.Dir(os.Args[0]), "mode"))
	emit := func(v map[string][]byte) int { json.NewEncoder(os.Stdout).Encode(v); return 0 }
	x963 := func(k *ecdsa.PrivateKey) []byte {
		b, _ := k.PublicKey.Bytes()
		return b
	}
	load := func() (*ecdsa.PrivateKey, error) {
		in, _ := io.ReadAll(os.Stdin)
		der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(in)))
		if err != nil {
			return nil, err
		}
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("corrupted objectID detected")
		}
		return k.(*ecdsa.PrivateKey), nil
	}
	if len(args) == 0 {
		return fail("usage")
	}
	switch args[0] {
	case "available": // like the real one: exit status only, nothing on stdout
		if string(mode) == "none" {
			return fail("this Mac has no Secure Enclave")
		}
		return 0
	case "create":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		return emit(map[string][]byte{"blob": der, "public": x963(k)})
	case "public":
		if string(mode) == "foreign" {
			return fail("corrupted objectID detected")
		}
		k, err := load()
		if err != nil {
			return fail(err.Error())
		}
		return emit(map[string][]byte{"public": x963(k)})
	case "sign":
		k, err := load()
		if err != nil {
			return fail(err.Error())
		}
		digest, err := hex.DecodeString(args[1])
		if err != nil || len(digest) != 32 {
			return fail("bad digest")
		}
		if string(mode) == "badsig" {
			k, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		sig, _ := ecdsa.SignASN1(rand.Reader, k, digest)
		return emit(map[string][]byte{"signature": sig})
	}
	return fail("unknown command")
}

// installHelper copies the test binary to dir/boundgate-sekey.
func installHelper(t *testing.T, perm os.FileMode) (helper, dir string) {
	t.Helper()
	dir = t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	helper = filepath.Join(dir, HelperName)
	if err := os.WriteFile(helper, b, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(helper, perm); err != nil { // WriteFile is subject to umask
		t.Fatal(err)
	}
	return helper, dir
}

func TestCreateLoadSign(t *testing.T) {
	helper, dir := installHelper(t, 0o755)
	path := filepath.Join(dir, "device.sekey")
	k1, err := New(helper, path).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !k1.HardwareBound() || k1.Kind() != "secure-enclave" {
		t.Fatalf("kind %q hardware %v", k1.Kind(), k1.HardwareBound())
	}
	if fi, _ := os.Stat(path); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v", fi)
	}
	// idempotent: the same identity after a restart
	k2, err := New(helper, path).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !k1.Public().(*ecdsa.PublicKey).Equal(k2.Public()) {
		t.Fatal("reopening the key file gave another public key")
	}
	digest := sha256.Sum256([]byte("hello"))
	sig, err := k2.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(k1.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("signature does not verify")
	}
	for _, c := range []struct {
		d    []byte
		opts crypto.SignerOpts
	}{{digest[:], crypto.SHA384}, {digest[:20], crypto.SHA256}, {digest[:], nil}} {
		if _, err := k2.Sign(rand.Reader, c.d, c.opts); err == nil {
			t.Fatalf("signed a %d byte digest with %v", len(c.d), c.opts)
		}
	}
}

// The key must work where the node uses it: as the client key of a TLS 1.3
// connection with a self-signed certificate.
func TestTLSClientAuth(t *testing.T) {
	helper, dir := installHelper(t, 0o755)
	key, err := New(helper, filepath.Join(dir, "device.sekey")).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mac"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &srvKey.PublicKey, srvKey)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert,
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			got <- nil
			return
		}
		got <- tc.ConnectionState().PeerCertificates[0].Raw
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if peer := <-got; string(peer) != string(der) {
		t.Fatal("the server did not see the device certificate")
	}
}

func TestHelperIsNotTrusted(t *testing.T) {
	helper, dir := installHelper(t, 0o755)
	path := filepath.Join(dir, "device.sekey")
	key, err := New(helper, path).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("x"))

	// a helper that signs with some other key
	os.WriteFile(filepath.Join(dir, "mode"), []byte("badsig"), 0o600)
	if _, err := key.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("a signature by another key was passed on: %v", err)
	}
	// the state directory on another Mac: its Secure Enclave does not know the blob
	os.WriteFile(filepath.Join(dir, "mode"), []byte("foreign"), 0o600)
	if _, err := New(helper, path).Open(context.Background()); err == nil || !strings.Contains(err.Error(), "another machine") {
		t.Fatalf("foreign blob: %v", err)
	}
	os.Remove(filepath.Join(dir, "mode"))

	// stored public key and blob do not belong together
	var f blobFile
	raw, _ := os.ReadFile(path)
	json.Unmarshal(raw, &f)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.Public, _ = other.PublicKey.Bytes()
	b, _ := json.Marshal(f)
	os.WriteFile(path, b, 0o600)
	if _, err := New(helper, path).Open(context.Background()); err == nil || !strings.Contains(err.Error(), "another public key") {
		t.Fatalf("swapped public key: %v", err)
	}
	// not a point on the curve
	f.Public = append([]byte{4}, make([]byte, 64)...)
	b, _ = json.Marshal(f)
	os.WriteFile(path, b, 0o600)
	if _, err := New(helper, path).Open(context.Background()); err == nil {
		t.Fatal("accepted a public key that is not on the curve")
	}
	// some other file
	os.WriteFile(path, []byte(`{"kind":"tpm2","blob":"AAAA"}`), 0o600)
	if _, err := New(helper, path).Open(context.Background()); err == nil {
		t.Fatal("accepted a key file of another kind")
	}
}

func TestHelperPath(t *testing.T) {
	helper, dir := installHelper(t, 0o775)
	path := filepath.Join(dir, "device.sekey")
	if _, err := New(helper, path).Open(context.Background()); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("group-writable helper: %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a key was created through a refused helper")
	}
	if _, err := New("boundgate-sekey", path).Open(context.Background()); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative helper: %v", err)
	}
	if _, err := New(filepath.Join(dir, "nope"), path).Open(context.Background()); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing helper: %v", err)
	}
	os.Chmod(helper, 0o644)
	if _, err := New(helper, path).Open(context.Background()); err == nil || !strings.Contains(err.Error(), "not an executable") {
		t.Fatalf("non-executable helper: %v", err)
	}
}

func TestAvailable(t *testing.T) {
	helper, dir := installHelper(t, 0o755)
	if !Available(context.Background(), helper) {
		t.Fatal("a working helper was reported as unavailable")
	}
	os.WriteFile(filepath.Join(dir, "mode"), []byte("none"), 0o600)
	if Available(context.Background(), helper) {
		t.Fatal("a Mac without Secure Enclave was reported as having one")
	}
	if Available(context.Background(), filepath.Join(dir, "missing")) {
		t.Fatal("a missing helper was reported as available")
	}
}
