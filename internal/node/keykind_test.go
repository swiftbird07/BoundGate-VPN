package node

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// key_kind auto never changes an identity that exists; what a fresh state
// directory gets depends on the machine (no Secure Enclave helper here).
func TestAutoKeyKindKeepsIdentity(t *testing.T) {
	for _, c := range []struct {
		files []string
		want  string
	}{
		{nil, "softkey"},
		{[]string{"device.key"}, "softkey"},
		{[]string{"device.sekey"}, "secure-enclave"},
		{[]string{"device.key", "device.sekey"}, "secure-enclave"}, // moved over, old file not yet removed
	} {
		dir := t.TempDir()
		for _, f := range c.files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cfg := Config{StateDir: dir, Log: slog.New(slog.DiscardHandler), SEKeyHelper: filepath.Join(dir, "no-helper")}
		if got := autoKeyKind(cfg); got != c.want {
			t.Errorf("state %v: auto chose %q, want %q", c.files, got, c.want)
		}
	}
}
