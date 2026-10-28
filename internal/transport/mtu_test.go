package transport

import (
	"encoding/binary"
	"testing"
)

func TestTooLargeAnswersIPv4WithASizeThatFits(t *testing.T) {
	pkt := make([]byte, 1300)
	pkt[0], pkt[9] = 0x45, 6 // IPv4, TCP
	binary.BigEndian.PutUint16(pkt[2:], 1300)
	copy(pkt[12:16], []byte{17, 57, 146, 58})
	copy(pkt[16:20], []byte{10, 25, 0, 1})
	got := tooLarge(pkt, 1300)
	if len(got) < 28 || got[20] != 3 || got[21] != 4 {
		t.Fatalf("not ICMP fragmentation needed: % x", got)
	}
	if mtu := binary.BigEndian.Uint16(got[26:]); mtu != FitMTU || int(mtu) >= len(pkt) {
		t.Fatalf("next-hop MTU %d: the sender must learn a size below the packet's %d", mtu, len(pkt))
	}
	if string(got[12:16]) != string(pkt[16:20]) || string(got[16:20]) != string(pkt[12:16]) {
		t.Fatal("must go from the packet's destination back to its source")
	}
	// a smaller path (a relay) is told as it is
	if mtu := binary.BigEndian.Uint16(tooLarge(pkt, 1100)[26:]); mtu != 1100 {
		t.Fatalf("next-hop MTU %d on a path that fits 1100", mtu)
	}
	v6 := make([]byte, 1300)
	v6[0] = 0x60
	if out := tooLarge(v6, 1200); out != nil {
		t.Fatal("the overlay carries IPv4 only: an IPv6 packet gets no answer")
	}
	// PacketSize QUIC packets: 37 bytes of packet overhead, 3 for the HTTP
	// datagram prefix
	if FitMTU > PacketSize-37-3 {
		t.Fatalf("FitMTU %d does not fit a connection without path MTU discovery", FitMTU)
	}
}
