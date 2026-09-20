package node

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// key_kind auto: a node bound to a control plane keeps the identity it
// enrolled with; otherwise the Secure Enclave wins where there is one.
func TestAutoKeyKind(t *testing.T) {
	for _, c := range []struct {
		files   []string
		enclave bool
		want    string
	}{
		{nil, false, "softkey"},
		{nil, true, "secure-enclave"},
		{[]string{"device.key"}, false, "softkey"},
		{[]string{"device.key", "control.pin"}, true, "softkey"}, // enrolled with it: an update must not change who this is
		{[]string{"device.key"}, true, "secure-enclave"},         // left over, no control plane knows it: seen on a real Mac
		{[]string{"device.sekey"}, true, "secure-enclave"},
		{[]string{"device.sekey"}, false, "secure-enclave"}, // the helper fails later and says why; never a second identity
		{[]string{"device.key", "device.sekey", "control.pin"}, true, "secure-enclave"},
	} {
		dir := t.TempDir()
		for _, f := range c.files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cfg := Config{StateDir: dir, Log: slog.New(slog.DiscardHandler)}
		if got := autoKeyKind(cfg, c.enclave); got != c.want {
			t.Errorf("state %v, enclave %v: auto chose %q, want %q", c.files, c.enclave, got, c.want)
		}
	}
	// provisioned pin = bound to a control plane by configuration
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "device.key"), []byte("x"), 0o600)
	if got := autoKeyKind(Config{StateDir: dir, ControlPin: "aa", Log: slog.New(slog.DiscardHandler)}, true); got != "softkey" {
		t.Errorf("provisioned pin: %q", got)
	}
}
