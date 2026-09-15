package netparse

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func v4(src, dst string, proto uint8, l4 []byte) []byte {
	p := make([]byte, 20+len(l4))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[9] = proto
	copy(p[12:16], netip.MustParseAddr(src).AsSlice())
	copy(p[16:20], netip.MustParseAddr(dst).AsSlice())
	copy(p[20:], l4)
	return p
}

func tcp(sp, dp uint16, flags uint8) []byte {
	l4 := make([]byte, 20)
	binary.BigEndian.PutUint16(l4[0:2], sp)
	binary.BigEndian.PutUint16(l4[2:4], dp)
	l4[12] = 5 << 4
	l4[13] = flags
	return l4
}

func TestParseIPv4TCP(t *testing.T) {
	h, ok := Parse(v4("100.96.0.2", "10.60.0.10", ProtoTCP, append(tcp(40000, 443, TCPSyn), 'x')))
	if !ok {
		t.Fatal("not ok")
	}
	if h.Version != 4 || h.Src != netip.MustParseAddr("100.96.0.2") || h.Dst != netip.MustParseAddr("10.60.0.10") {
		t.Fatalf("%+v", h)
	}
	if h.Proto != ProtoTCP || h.SrcPort != 40000 || h.DstPort != 443 || h.TCPFlags != TCPSyn || h.Payload != 40 {
		t.Fatalf("%+v", h)
	}
}

func TestParseIPv4UDPAndFragment(t *testing.T) {
	l4 := make([]byte, 8)
	binary.BigEndian.PutUint16(l4[2:4], 53)
	h, ok := Parse(v4("100.96.0.2", "10.0.0.53", ProtoUDP, l4))
	if !ok || h.DstPort != 53 || h.Payload != 28 {
		t.Fatalf("%+v %v", h, ok)
	}
	frag := v4("100.96.0.2", "10.0.0.53", ProtoUDP, l4)
	binary.BigEndian.PutUint16(frag[6:8], 0x0010) // fragment offset 16
	h, ok = Parse(frag)
	if !ok || h.DstPort != 0 || h.Payload != -1 {
		t.Fatalf("fragment parsed ports: %+v", h)
	}
}

func TestParseIPv6(t *testing.T) {
	p := make([]byte, 40+20)
	p[0] = 0x60
	p[6] = ProtoTCP
	copy(p[8:24], netip.MustParseAddr("fd00::2").AsSlice())
	copy(p[24:40], netip.MustParseAddr("fd00::1").AsSlice())
	copy(p[40:], tcp(1, 22, TCPAck))
	h, ok := Parse(p)
	if !ok || h.Version != 6 || h.DstPort != 22 || h.Src != netip.MustParseAddr("fd00::2") {
		t.Fatalf("%+v %v", h, ok)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {}, {0x45}, make([]byte, 19), {0x00, 1, 2, 3}, append([]byte{0x4f}, make([]byte, 19)...)} {
		if _, ok := Parse(b); ok {
			t.Fatalf("accepted %x", b)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(v4("1.2.3.4", "5.6.7.8", ProtoTCP, tcp(1, 2, 0)))
	f.Add([]byte{0x60, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, ok := Parse(b)
		if ok && h.Payload > len(b) {
			t.Fatalf("payload offset %d beyond packet %d", h.Payload, len(b))
		}
	})
}
