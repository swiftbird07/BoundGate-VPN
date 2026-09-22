package ipc

import (
	"context"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/update"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
)

func TestSettingsValidate(t *testing.T) {
	for in, want := range map[string]string{
		"bg.example.com":           "bg.example.com",
		" https://bg.example.com/": "bg.example.com",
		"bg.example.com:8443":      "bg.example.com:8443",
		"203.0.113.7:443":          "203.0.113.7:443",
		"[2001:db8::1]:443":        "[2001:db8::1]:443",
		"Vpn.Net407.com:443":       "vpn.net407.com:443", // a keyboard's capitals: the node name must still match
	} {
		s := Settings{ControlAddr: in}
		if err := s.Validate(); err != nil || s.ControlAddr != want {
			t.Errorf("%q: got %q, %v", in, s.ControlAddr, err)
		}
	}
	for _, bad := range []string{"", "  ", "bad host", "user@host", "host/path", "host:0", "host:70000", "host:abc", "https://"} {
		s := Settings{ControlAddr: bad}
		if err := s.Validate(); err == nil {
			t.Errorf("%q accepted as %q", bad, s.ControlAddr)
		}
	}
}

// Setup mode: status says unconfigured, everything else explains itself,
// configure validates, stores and ends the setup server.
func TestServeSetup(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "bgipc") // unix socket paths are short
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s")
	settingsPath := filepath.Join(dir, "state", "settings.json")
	type result struct {
		s   Settings
		err error
	}
	done := make(chan result, 1)
	go func() {
		s, err := ServeSetup(context.Background(), sock, Options{}, node.Status{NodeName: "mac"}, &update.Service{Current: "v1.0.0"}, func(s Settings) error { return SaveSettings(settingsPath, s) })
		done <- result{s, err}
	}()
	c := NewClient(sock)
	var st node.Status
	for i := 0; ; i++ {
		if st, err = c.Status(); err == nil {
			break
		}
		if i > 50 {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st.State != StateUnconfigured || st.NodeName != "mac" {
		t.Fatalf("%+v", st)
	}
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v", fi.Mode())
	}
	if _, err := c.Up(""); err == nil || !strings.Contains(err.Error(), "configure") {
		t.Fatalf("up in setup mode: %v", err)
	}
	// an update needs no control plane: the socket of setup mode answers for it
	if u, err := c.Update(false); err != nil || u.Current != "v1.0.0" {
		t.Fatalf("update status in setup mode: %+v, %v", u, err)
	}
	if err := c.Configure(Settings{ControlAddr: "not a host"}); err == nil {
		t.Fatal("invalid address accepted")
	}
	if err := c.Reset(false); err == nil {
		t.Fatal("reset in setup mode accepted")
	}
	if err := c.Configure(Settings{ControlAddr: "https://bg.example.com/", Name: " mac "}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil || r.s.ControlAddr != "bg.example.com" || r.s.Name != "mac" {
			t.Fatalf("%+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("setup server did not end after configure")
	}
	got, err := LoadSettings(settingsPath)
	if err != nil || got.ControlAddr != "bg.example.com" {
		t.Fatalf("%+v %v", got, err)
	}
	if fi, _ := os.Stat(settingsPath); fi.Mode().Perm() != 0o600 {
		t.Fatalf("settings mode %v", fi.Mode())
	}
	if empty, err := LoadSettings(filepath.Join(dir, "none.json")); err != nil || empty.ControlAddr != "" {
		t.Fatal("missing settings file must read as empty")
	}
}
