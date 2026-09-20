package controlclient

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A long-poll that waits on a connection from before a route change is cut
// off by Reconnect and asked again at once, instead of sitting out its
// deadline (what a Mac showed as "snapshot…: context deadline exceeded" after
// every connect and disconnect).
func TestReconnectRepeatsTheLongPoll(t *testing.T) {
	var calls atomic.Int32
	arrived := make(chan struct{}, 4)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		arrived <- struct{}{}
		if n == 1 {
			<-r.Context().Done() // the answer that never comes
			return
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	c := New(Config{Addr: strings.TrimPrefix(srv.URL, "https://"), TLS: &tls.Config{InsecureSkipVerify: true}})
	defer c.Close()
	var reported atomic.Int32
	c.onError = func(err error) {
		if err != nil {
			reported.Add(1)
		}
	}
	type result struct {
		err error
		nil bool
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		snap, err := c.Snapshot(context.Background(), 4, 30*time.Second)
		done <- result{err, snap == nil}
	}()
	select {
	case <-arrived:
	case <-time.After(20 * time.Second):
		t.Fatal("the long-poll never arrived (no fallback to TCP?)")
	}
	c.Reconnect()
	select {
	case r := <-done:
		if r.err != nil || !r.nil {
			t.Fatalf("got %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the long-poll was not repeated after Reconnect")
	}
	if calls.Load() != 2 || reported.Load() != 0 {
		t.Fatalf("calls %d, errors reported %d", calls.Load(), reported.Load())
	}
	t.Logf("answered after %s", time.Since(start).Round(time.Millisecond))
}

// Our own deadline reads as what happened, not as Go's error chain.
func TestNoAnswerMessage(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	c := New(Config{Addr: strings.TrimPrefix(srv.URL, "https://"), TLS: &tls.Config{InsecureSkipVerify: true}})
	defer c.Close()
	_, err := c.do(context.Background(), http.MethodGet, "/api/v1/node/snapshot?since=4&wait=30s", nil, nil, 8*time.Second)
	if err == nil || !strings.Contains(err.Error(), "gave no answer within 8s (GET /api/v1/node/snapshot)") || strings.Contains(err.Error(), "since=") {
		t.Fatalf("got %v", err)
	}
}
