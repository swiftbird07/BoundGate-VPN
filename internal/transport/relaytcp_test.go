package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

// A quiet relay stream on the TCP fallback stays open: a listener carries
// something only while a dialer talks to it, and the idle deadline ended it.
func TestAQuietRelayStreamStaysOpen(t *testing.T) {
	a, b := net.Pipe()
	hub := newCapsuleStream(a, nil, 200*time.Millisecond)
	defer hub.Close()
	node := newCapsuleStream(b, nil, 200*time.Millisecond)
	defer node.Close()
	time.Sleep(time.Second)
	for _, s := range []*capsuleStream{hub, node} {
		select {
		case <-s.done:
			t.Fatal("a quiet stream ended at its idle timeout")
		default:
		}
	}
	if err := hub.SendDatagram([]byte{0, 1, 2}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if got, err := node.ReceiveDatagram(ctx); err != nil || len(got) != 3 {
		t.Fatalf("after the quiet: %v %v", got, err)
	}
}

// A dialer that stops reading does not hold up the hub, which relays to all
// of a listener's dialers from one goroutine.
func TestSendingToADialerThatDoesNotReadNeverWaits(t *testing.T) {
	a, b := net.Pipe() // nobody reads b
	defer b.Close()
	s := newCapsuleStream(a, nil, time.Minute)
	defer s.Close()
	done := make(chan struct{})
	go func() {
		for range 4 * capsuleQueue {
			_ = s.SendDatagram(make([]byte, 1200))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SendDatagram waited for a dialer that does not read")
	}
	if s.dropped.Load() == 0 {
		t.Fatal("nothing was dropped although nothing could be sent")
	}
}
