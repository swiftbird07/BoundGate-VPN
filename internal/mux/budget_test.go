package mux

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// firstInitial is the first datagram a QUIC client sends: with a post-
// quantum key share its ClientHello does not fit, so the front must wait
// for the next one before it knows the name.
func firstInitial(t *testing.T) []byte {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		_, _ = quic.DialAddr(ctx, pc.LocalAddr().String(), &tls.Config{ServerName: "hub.example", NextProtos: []string{"h3"}}, nil)
	}()
	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

// A flood of first Initials from many (spoofed) addresses holds no more
// than the budget, and what it holds is given back when the flows go.
func TestHandshakesShareABudget(t *testing.T) {
	pkt := firstInitial(t)
	fr := &Front{cfg: Config{}, byID: map[byte]*backend{}, byName: map[string]*backend{}, wild: map[string]*backend{}, initial: map[flowKey]*flow{}}
	fr.routeUDP(netip.MustParseAddrPort("192.0.2.1:1"), pkt)
	if len(fr.initial) != 1 || fr.buffered == 0 {
		t.Skipf("the client's first Initial carries the whole ClientHello here (%d flows, %d bytes held)", len(fr.initial), fr.buffered)
	}
	per := fr.buffered
	defer func(v int) { maxBuffered = v }(maxBuffered)
	maxBuffered = 10 * per
	for i := 2; i < 100; i++ {
		fr.routeUDP(netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 1), pkt)
	}
	if fr.buffered > maxBuffered || len(fr.initial) > 10 {
		t.Fatalf("%d bytes in %d flows held, the budget is %d", fr.buffered, len(fr.initial), maxBuffered)
	}
	sum := 0
	for _, fl := range fr.initial {
		sum += fl.size()
	}
	if sum != fr.buffered {
		t.Fatalf("accounted %d, held %d", fr.buffered, sum)
	}
	fr.mu.Lock()
	for k, fl := range fr.initial {
		fr.forget(k, fl)
	}
	fr.mu.Unlock()
	if fr.buffered != 0 {
		t.Fatalf("%d bytes still accounted after every flow went", fr.buffered)
	}
}

// A table full of flows that never got their name (a flood from spoofed
// addresses) still takes a client's first Initial: one of them makes room.
func TestAFullTableStillTakesANewClient(t *testing.T) {
	pkt := firstInitial(t)
	fr := &Front{cfg: Config{}, byID: map[byte]*backend{}, byName: map[string]*backend{}, wild: map[string]*backend{}, initial: map[flowKey]*flow{}}
	for i := range maxFlows {
		fr.initial[flowKey{netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), 1), "x"}] = &flow{expires: time.Now().Add(flowTTL)}
	}
	client := netip.MustParseAddrPort("192.0.2.1:443")
	fr.routeUDP(client, pkt)
	found := false
	for k := range fr.initial {
		if k.client == client {
			found = true
		}
	}
	if !found || len(fr.initial) != maxFlows {
		t.Fatalf("the new client was refused: found %v, %d flows", found, len(fr.initial))
	}
	if len(pkt) < minInitial {
		t.Fatalf("a real client's first datagram has %d bytes, below the minimum", len(pkt))
	}
	// shorter than RFC 9000 allows: not even looked at
	before := len(fr.initial)
	fr.routeUDP(netip.MustParseAddrPort("192.0.2.2:443"), pkt[:minInitial-1])
	if len(fr.initial) != before {
		t.Fatal("a short Initial took a flow")
	}
}
