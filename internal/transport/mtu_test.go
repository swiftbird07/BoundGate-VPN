package transport

import (
	"encoding/binary"
	"testing"
)

func TestTooLargeAnswersIPv4WithASizeThatFits(t *testing.T) {
	pkt := make([]byte, 1280)
	pkt[0], pkt[9] = 0x45, 6 // IPv4, TCP
	binary.BigEndian.PutUint16(pkt[2:], 1280)
	copy(pkt[12:16], []byte{17, 57, 146, 58})
	copy(pkt[16:20], []byte{10, 25, 0, 1})
	if tooLarge(pkt, nil) != nil {
		t.Fatal("a packet that was sent needs no answer")
	}
	theirs := []byte{0x45, 0} // connect-ip-go's "MTU 1280"
	got := tooLarge(pkt, theirs)
	if len(got) < 28 || got[20] != 3 || got[21] != 4 {
		t.Fatalf("not ICMP fragmentation needed: % x", got)
	}
	if mtu := binary.BigEndian.Uint16(got[26:]); mtu != FitMTU || int(mtu) >= len(pkt) {
		t.Fatalf("next-hop MTU %d: the sender must learn a size below the packet's %d", mtu, len(pkt))
	}
	if string(got[12:16]) != string(pkt[16:20]) || string(got[16:20]) != string(pkt[12:16]) {
		t.Fatal("must go from the packet's destination back to its source")
	}
	v6 := make([]byte, 1300)
	v6[0] = 0x60
	if out := tooLarge(v6, theirs); &out[0] != &theirs[0] {
		t.Fatal("IPv6: 1280 is the right answer, keep it")
	}
	// 1280-byte QUIC packets: 1243 per datagram, 3 for the HTTP datagram prefix
	if FitMTU > 1243-3 {
		t.Fatalf("FitMTU %d does not fit a connection without path MTU discovery", FitMTU)
	}
}
