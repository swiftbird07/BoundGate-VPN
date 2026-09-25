package main

import "sync"

// gate admits calls into the app's callbacks until it is closed. The app
// frees what the callbacks reach (ctx, the Go copy of bg_platform) once
// bg_stop returns, but the engine's logger outlives the engine: goroutines
// of libraries that were not joined, the standard log package (it writes to
// the logger of the engine started last) and requests still in flight all
// may log later. close refuses every new call and waits for those in flight,
// so that no callback runs after bg_stop, and none on freed memory.
//
// A callback may call into the core again (enter nests); one that calls
// bg_stop of its own engine waits for itself, as boundgate.h says.
type gate struct {
	mu     sync.Mutex
	idle   sync.Cond
	calls  int
	closed bool
}

func newGate() *gate {
	g := &gate{}
	g.idle.L = &g.mu
	return g
}

// enter reports whether the callback may run; leave must follow a true.
func (g *gate) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.calls++
	return true
}

func (g *gate) leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls--
	if g.calls == 0 {
		g.idle.Broadcast()
	}
}

// close returns once no callback runs and none will again.
func (g *gate) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	for g.calls > 0 {
		g.idle.Wait()
	}
}
