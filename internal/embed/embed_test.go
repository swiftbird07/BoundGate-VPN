package embed

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
)

type testPlatform struct {
	priv  *ecdsa.PrivateKey
	mu    sync.Mutex
	lines []string
	signs int
}

func newTestPlatform(t *testing.T) *testPlatform {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testPlatform{priv: k}
}

func (p *testPlatform) Apply(netcfg.NetworkSettings) (int, error) {
	return -1, errors.New("this test brings no tunnel up")
}
func (p *testPlatform) Release() {}
func (p *testPlatform) PublicKey() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&p.priv.PublicKey)
}
func (p *testPlatform) Sign(d []byte) ([]byte, error) {
	p.mu.Lock()
	p.signs++
	p.mu.Unlock()
	return ecdsa.SignASN1(rand.Reader, p.priv, d)
}
func (p *testPlatform) KeyKind() string     { return "secure-enclave" }
func (p *testPlatform) HardwareBound() bool { return true }
func (p *testPlatform) Log(level int, line string) {
	p.mu.Lock()
	p.lines = append(p.lines, line)
	p.mu.Unlock()
}

func status(t *testing.T, e *Engine) map[string]any {
	t.Helper()
	code, body := e.Request("GET", "/v1/status", nil)
	if code != http.StatusOK {
		t.Fatalf("status: %d %s", code, body)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEngineSetupConfigureAndReset(t *testing.T) {
	dir := t.TempDir()
	p := newTestPlatform(t)
	cfg := Config{StateDir: dir, Platform: "ios", Name: "Ada's iPhone", LogLevel: "debug"}
	e, err := Start(cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	st := status(t, e)
	if st["state"] != "unconfigured" || st["key_kind"] != "secure-enclave" || st["hardware_bound"] != true || st["fingerprint"] == "" {
		t.Fatalf("setup status %v", st)
	}
	// the app and the extension share the directory: one engine at a time
	if _, err := Start(cfg, p); !errors.Is(err, ErrBusy) {
		t.Fatalf("second engine: %v", err)
	}

	// configure: the node takes over, with the platform's key
	code, body := e.Request("POST", "/v1/configure", []byte(`{"control_addr":"127.0.0.1:1"}`))
	if code != http.StatusOK {
		t.Fatalf("configure: %d %s", code, body)
	}
	st = status(t, e)
	if st["state"] != "down" || st["control"] != "127.0.0.1:1" || st["node_name"] != "Ada's iPhone" || st["key_kind"] != "secure-enclave" {
		t.Fatalf("node status %v", st)
	}
	if p.signs == 0 {
		t.Fatal("the device certificate was not signed by the platform's key")
	}
	// the certificate the node presents carries the platform's public key
	pub, _ := p.PublicKey()
	sum := sha256.Sum256(pub)
	if !strings.EqualFold(strings.ReplaceAll(st["fingerprint"].(string), " ", ""), strings.ReplaceAll(x509Hex(sum[:]), " ", "")) {
		t.Fatalf("fingerprint %v is not the platform key's", st["fingerprint"])
	}

	// a second engine after a restart finds the settings
	e.Stop()
	e, err = Start(cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	if st := status(t, e); st["control"] != "127.0.0.1:1" {
		t.Fatalf("after restart %v", st)
	}
	// reset: back to setup, the key stays
	if code, body := e.Request("POST", "/v1/reset", []byte(`{"new_identity":true}`)); code == http.StatusOK {
		t.Fatalf("a new identity is the app's business: %s", body)
	}
	if code, body := e.Request("POST", "/v1/reset", nil); code != http.StatusOK {
		t.Fatalf("reset: %d %s", code, body)
	}
	deadline := time.Now().Add(3 * time.Second)
	for status(t, e)["state"] != "unconfigured" {
		if time.Now().After(deadline) {
			t.Fatal("still configured after reset")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(p.lines) == 0 || !strings.Contains(strings.Join(p.lines, "\n"), "level=") {
		t.Fatalf("no log lines reached the platform: %q", p.lines)
	}
	for _, l := range p.lines {
		if strings.HasPrefix(l, "time=") {
			t.Fatalf("the platform's log has its own time: %q", l)
		}
	}
	e.Stop()
	if code, _ := e.Request("GET", "/v1/status", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("a stopped engine answered %d", code)
	}
}

func TestPlatformKeyRefusesOtherKeys(t *testing.T) {
	p := newTestPlatform(t)
	k, err := newPlatformKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Sign(nil, make([]byte, 48), nil); err == nil {
		t.Fatal("signed something that is not a SHA-256 digest")
	}
	rsaLike := &wrongKey{testPlatform: p}
	if _, err := newPlatformKey(rsaLike); err == nil {
		t.Fatal("accepted a P-384 key")
	}
}

type wrongKey struct{ *testPlatform }

func (w *wrongKey) PublicKey() ([]byte, error) {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	return x509.MarshalPKIXPublicKey(&k.PublicKey)
}

func x509Hex(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexd[c>>4], hexd[c&15])
	}
	return string(out)
}
