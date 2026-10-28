package transport

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
)

// A peer on the TCP fallback that stops reading must not stop the node
// that writes to it: the hub writes into every tunnel from one goroutine.
func TestWritePacketNeverWaitsForThePeer(t *testing.T) {
	a, b := net.Pipe() // unbuffered: a write waits until the other end reads
	defer b.Close()
	l := newCapsuleLink(a, nil, time.Minute, 0, true)
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

// Closing a link whose incoming queue is full, with nobody reading it (the
// node stopped taking packets from it), must not wait for a reader.
func TestCloseDoesNotWaitForAReader(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	l := newCapsuleLink(a, nil, time.Minute, 0, true)
	sender := newCapsuleLink(b, nil, time.Minute, 0, false)
	defer sender.Close(quic.ApplicationErrorCode(0), "")
	// what the peer may send: from anywhere to anywhere
	if err := l.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}); err != nil {
		t.Fatal(err)
	}
	if err := l.AdvertiseRoute([]connectip.IPRoute{{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")}}); err != nil {
		t.Fatal(err)
	}
	pkt := make([]byte, 100)
	pkt[0] = 0x45
	// fill the queue, then one more that the read loop holds, waiting to
	// queue it (the sender drops what does not fit its own queue: send in
	// rounds)
	deadline := time.Now().Add(5 * time.Second)
	for len(l.in) < capsuleQueue && time.Now().Before(deadline) {
		pkt[8] = 64
		_, _ = sender.WritePacket(pkt)
		time.Sleep(time.Millisecond)
	}
	if len(l.in) < capsuleQueue {
		t.Fatalf("queue did not fill: %d", len(l.in))
	}
	pkt[8] = 64
	_, _ = sender.WritePacket(pkt)
	for len(sender.out) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	closed := make(chan struct{})
	go func() {
		_ = l.Close(quic.ApplicationErrorCode(0), "bye")
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for somebody to read the incoming queue")
	}
}

// The TCP fallback carries what QUIC carries: a peer's packet from an
// address it was not assigned, or to one outside what it was advertised,
// is dropped on the hub, and the hub's packet to an address the client was
// not assigned is dropped on the client (connect-ip-go does the same on
// QUIC).
func TestCapsulePacketsKeepToAssignedAndAdvertised(t *testing.T) {
	a, b := net.Pipe()
	hub := newCapsuleLink(a, nil, time.Minute, 0, true)
	defer hub.Close(0, "")
	client := newCapsuleLink(b, nil, time.Minute, 0, false)
	defer client.Close(0, "")
	if err := hub.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")}); err != nil {
		t.Fatal(err)
	}
	if err := hub.AdvertiseRoute([]connectip.IPRoute{
		{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.255.255.255")},
		{StartIP: netip.MustParseAddr("192.168.1.0"), EndIP: netip.MustParseAddr("192.168.1.255"), IPProtocol: 6},
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.LocalPrefixes(ctx); err != nil {
		t.Fatal(err)
	}
	pkt := func(src, dst string, proto byte, mark byte) []byte {
		p := make([]byte, 21)
		p[0], p[8], p[9], p[20] = 0x45, 64, proto, mark
		copy(p[12:16], netip.MustParseAddr(src).AsSlice())
		copy(p[16:20], netip.MustParseAddr(dst).AsSlice())
		return p
	}
	send := []struct {
		p    []byte
		pass bool
	}{
		{pkt("100.96.0.3", "10.0.0.1", 17, 1), false},    // not its address
		{pkt("100.96.0.2", "172.16.0.1", 17, 2), false},  // not advertised
		{pkt("100.96.0.2", "192.168.1.5", 17, 3), false}, // route for TCP only
		{pkt("100.96.0.2", "192.168.1.5", 6, 4), true},
		{pkt("100.96.0.2", "192.168.1.5", 1, 5), true}, // ICMP always
		{pkt("100.96.0.2", "10.0.0.1", 17, 6), true},
	}
	for _, s := range send {
		if _, err := client.WritePacket(s.p); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 100)
	var got []byte
	for range 3 {
		n, err := hub.ReadPacket(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buf[n-1])
	}
	if string(got) != "\x04\x05\x06" {
		t.Fatalf("hub took packets %v, want 4 5 6", got)
	}
	// and the other way: only to the client's own address
	for _, p := range [][]byte{pkt("10.0.0.1", "100.96.0.9", 17, 7), pkt("10.0.0.1", "100.96.0.2", 17, 8)} {
		if _, err := hub.WritePacket(p); err != nil {
			t.Fatal(err)
		}
	}
	n, err := client.ReadPacket(buf)
	if err != nil || buf[n-1] != 8 {
		t.Fatalf("client took %v (%v), want packet 8", buf[:n], err)
	}
}
