//go:build linux

package netcfg

import (
	"strings"
	"testing"
)

// The routing tables are opened once (before the worker's sandbox) and read
// from their start at every look.
func TestRouteTablesAreReadAgain(t *testing.T) {
	c, err := NewWatcher()
	if err != nil {
		t.Skip(err)
	}
	tables := c.(linuxCfg).tables
	for i := 0; i < 3; i++ {
		r4, _, err := tables.read()
		if err != nil || !strings.HasPrefix(r4, "Iface") {
			t.Fatalf("look %d: %q %v", i, r4, err)
		}
	}
	if _, err := c.(linuxCfg).defaults(); err != nil {
		t.Fatal(err)
	}
}
