package node

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
)

// recordNet records host route changes; everything else is the embedded nil
// Configurator and must not be called.
type recordNet struct {
	netcfg.Configurator
	mu  sync.Mutex
	ops []string
}

func (r *recordNet) AddBypass(_ context.Context, ip netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, "add "+ip.String())
	return nil
}

func (r *recordNet) DelBypass(_ context.Context, ip netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, "del "+ip.String())
	return nil
}

// After a change of network every host route is set again, so that it
// follows the new gateway; a session that is ending is left alone.
func TestRepinBypass(t *testing.T) {
	rec := &recordNet{}
	n := &Node{net: rec, log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	hub := netip.MustParseAddr("203.0.113.7")
	s := &session{n: n, ctx: ctx, cancel: cancel, bypass: map[netip.Addr]bool{hub: true}}
	s.repinBypass()
	if len(rec.ops) != 2 || rec.ops[0] != "del 203.0.113.7" || rec.ops[1] != "add 203.0.113.7" {
		t.Fatalf("ops %v", rec.ops)
	}
	cancel()
	s.repinBypass()
	if len(rec.ops) != 2 {
		t.Fatalf("an ending session got its routes back: %v", rec.ops)
	}
}
