package transport

import (
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// A peer on the TCP fallback that stops reading must not stop the node
// that writes to it: the hub writes into every tunnel from one goroutine.
func TestWritePacketNeverWaitsForThePeer(t *testing.T) {
	a, b := net.Pipe() // unbuffered: a write waits until the other end reads
	defer b.Close()
	l := newCapsuleLink(a, nil, time.Minute, 0)
	pkt := make([]byte, 1200)
	pkt[0], pkt[8] = 0x45, 64
	done := make(chan struct{})
	go func() {
		for range 4 * capsuleQueue {
			pkt[8] = 64 // WritePacket counts the TTL down, as a router does
			if _, err := l.WritePacket(pkt); err != nil {
				t.Error(err)
				break
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("WritePacket blocked on a peer that does not read")
	}
	if l.dropped.Load() == 0 {
		t.Fatal("nothing was dropped although nothing could be sent")
	}
	// and closing does not wait for it either
	closed := make(chan struct{})
	go func() {
		_ = l.Close(quic.ApplicationErrorCode(0), "bye")
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for a peer that does not read")
	}
}
