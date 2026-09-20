package netparse

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestFragNeeded(t *testing.T) {
	pkt := make([]byte, 1300)
	pkt[0], pkt[8], pkt[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	copy(pkt[12:], []byte{10, 21, 0, 5})
	copy(pkt[16:], []byte{10, 21, 0, 4})
	binary.BigEndian.PutUint16(pkt[20:], 40000)
	binary.BigEndian.PutUint16(pkt[22:], 443)

	out := FragNeeded(pkt, 1100)
	h, ok := Parse(out)
	if !ok || h.Src != netip.MustParseAddr("10.21.0.4") || h.Dst != netip.MustParseAddr("10.21.0.5") {
		t.Fatalf("answer goes from the destination to the source: %+v %v", h, ok)
	}
	if len(out) != 20+8+28 || out[20] != 3 || out[21] != 4 || binary.BigEndian.Uint16(out[26:]) != 1100 {
		t.Fatalf("not a fragmentation-needed message with the MTU: % x", out[:28])
	}
	// a correct Internet checksum sums to zero over the covered bytes
	if Checksum(out[:20], 0) != 0 || Checksum(out[20:], 0) != 0 {
		t.Fatal("checksums do not verify")
	}
	if string(out[28:]) != string(pkt[:28]) {
		t.Fatal("quote is not the header plus 8 bytes")
	}
	// never answer an ICMP error, a short packet or IPv6
	out[9] = 1
	if FragNeeded(out, 1100) != nil || FragNeeded(pkt[:10], 1100) != nil || FragNeeded(append([]byte{0x60}, pkt[1:]...), 1100) != nil {
		t.Fatal("answered something that must stay unanswered")
	}
	// an echo request is a query and gets the answer
	pkt[9], pkt[20] = 1, 8
	if FragNeeded(pkt, 1100) == nil {
		t.Fatal("echo request got no answer")
	}
}
