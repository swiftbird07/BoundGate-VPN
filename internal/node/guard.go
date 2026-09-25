package node

import (
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync/atomic"
	"time"
)

// packetGuard turns a panic while one packet is handled into a dropped
// packet. Every packet from a tunnel, a path or the host stack is parsed
// and decided here from bytes someone else chose; a bug in that code must
// cost the packet, not the process: a crash takes every tunnel of a hub
// down, and a full-tunnel spoke's traffic leaves unprotected until the
// daemon is back. Only the per-packet boundary recovers: state that a
// panic may leave half-changed is behind deferred unlocks there.
type packetGuard struct {
	log    *slog.Logger
	panics atomic.Uint64
	logged atomic.Int64 // when the last panic was logged (unix ns)
}

// catch must be deferred directly by the function that handles one packet.
// It logs the first panic and then at most one per 10 s, with the stack but
// none of the packet's bytes.
func (g *packetGuard) catch(where string) {
	r := recover()
	if r == nil {
		return
	}
	n := g.panics.Add(1)
	now, last := time.Now().UnixNano(), g.logged.Load()
	if n > 1 && now-last < int64(10*time.Second) || !g.logged.CompareAndSwap(last, now) {
		return
	}
	stack := debug.Stack()
	if len(stack) > 8<<10 {
		stack = stack[:8<<10]
	}
	g.log.Error("packet dropped: handling it panicked; this is a bug, please report it", "where", where, "panic", fmt.Sprint(r), "panics", n, "stack", string(stack))
}
