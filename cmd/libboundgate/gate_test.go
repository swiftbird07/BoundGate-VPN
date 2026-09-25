package main

import (
	"testing"
	"time"
)

// bg_stop frees what the callbacks reach once close returns: a callback in
// flight finishes first, and none starts afterwards.
func TestGateCloseWaitsForCallsInFlight(t *testing.T) {
	g := newGate()
	if !g.enter() {
		t.Fatal("an open gate refused a call")
	}
	if !g.enter() { // a callback that calls into the core again
		t.Fatal("a nested call was refused")
	}
	closed := make(chan struct{})
	go func() { g.close(); close(closed) }()

	// close has begun (or is about to): a call now must not start, and must
	// not wait for close either (that would deadlock a nested call)
	deadline := time.Now().Add(2 * time.Second)
	for {
		g.mu.Lock()
		c := g.closed
		g.mu.Unlock()
		if c {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("close did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if g.enter() {
		t.Fatal("a call started while the gate was closing")
	}

	g.leave()
	select {
	case <-closed:
		t.Fatal("close returned while a call was still in flight")
	case <-time.After(50 * time.Millisecond):
	}
	g.leave()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("close did not return after the last call")
	}
	if g.enter() {
		t.Fatal("a call started after close")
	}
}

func TestGateCloseWithoutCalls(t *testing.T) {
	g := newGate()
	g.enter()
	g.leave()
	done := make(chan struct{})
	go func() { g.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("close of an idle gate blocked")
	}
}
