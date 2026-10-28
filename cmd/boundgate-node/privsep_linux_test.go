package main

import (
	"context"
	"testing"
)

// The parent answers its worker past the stop signal: the worker's
// teardown is a series of requests to it.
func TestTheParentServesThroughTheWorkersTeardown(t *testing.T) {
	stop, signal := context.WithCancel(context.Background())
	sctx, cancel := serveContext(stop)
	signal()
	if sctx.Err() != nil {
		t.Fatal("the stop signal ended the parent's answers before the worker was gone")
	}
	cancel()
	if sctx.Err() == nil {
		t.Fatal("the parent never stops answering")
	}
}
