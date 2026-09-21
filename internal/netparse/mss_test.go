package netparse

import (
	"encoding/binary"
	"testing"
)

// syn builds an IPv4 TCP SYN with the given options and a correct checksum.
func syn(opts []byte, flags byte) []byte {
	for len(opts)%4 != 0 {
		opts = append(opts, 0)
	}
	tcpLen := 20 + len(opts)
	b := make([]byte, 20+tcpLen)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8], b[9] = 64, ProtoTCP
	copy(b[12:], []byte{10, 25, 0, 1})
	copy(b[16:], []byte{193, 99, 144, 85})
	t := b[20:]
	binary.BigEndian.PutUint16(t[0:], 50273)
	binary.BigEndian.PutUint16(t[2:], 443)
	t[12] = byte(tcpLen/4) << 4
	t[13] = flags
	copy(t[20:], opts)
	binary.BigEndian.PutUint16(t[16:], tcpChecksum(b))
	return b
}

func tcpChecksum(b []byte) uint16 {
	t := append([]byte(nil), b[20:]...)
	t[16], t[17] = 0, 0
	pseudo := make([]byte, 12)
	copy(pseudo[0:], b[12:20])
	pseudo[9] = ProtoTCP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(t)))
	return Checksum(t, ^Checksum(pseudo, 0))
}

func TestClampMSS(t *testing.T) {
	mssOpt := []byte{2, 4, 0x04, 0xd8} // 1240
	cases := []struct {
		name    string
		opts    []byte
		flags   byte
		want    bool
		wantMSS uint16
	}{
		{"syn, option first", append(append([]byte{}, mssOpt...), 1, 3, 3, 6), TCPSyn, true, 1190},
		{"syn-ack, option at an odd offset", append([]byte{1}, append(append([]byte{}, mssOpt...), 1, 1, 1)...), TCPSyn | TCPAck, true, 1190},
		{"already small enough", []byte{2, 4, 0x02, 0x18}, TCPSyn, false, 536},
		{"not a syn", append([]byte{}, mssOpt...), TCPAck, false, 1240},
		{"no option", []byte{1, 1, 1, 1}, TCPSyn, false, 0},
		{"broken option length", []byte{2, 9, 0x04, 0xd8}, TCPSyn, false, 0},
	}
	for _, c := range cases {
		pkt := syn(c.opts, c.flags)
		h, ok := Parse(pkt)
		if !ok {
			t.Fatalf("%s: parse", c.name)
		}
		if got := ClampMSS(h, pkt, 1190); got != c.want {
			t.Fatalf("%s: changed = %v, want %v", c.name, got, c.want)
		}
		if got, want := binary.BigEndian.Uint16(pkt[36:]), tcpChecksum(pkt); got != want {
			t.Fatalf("%s: checksum %04x, a fresh one is %04x", c.name, got, want)
		}
		if c.want {
			i := 40
			if c.opts[0] == 1 {
				i = 41
			}
			if got := binary.BigEndian.Uint16(pkt[i+2:]); got != c.wantMSS {
				t.Fatalf("%s: mss %d, want %d", c.name, got, c.wantMSS)
			}
		}
	}
}

func TestParseFragments(t *testing.T) {
	pkt := syn(nil, TCPAck)
	binary.BigEndian.PutUint16(pkt[4:], 49804)
	binary.BigEndian.PutUint16(pkt[6:], 0x2000) // first fragment: MF, offset 0
	h, _ := Parse(pkt)
	if h.Fragment() || !h.MoreFragments || h.FragID != 49804 || h.DstPort != 443 {
		t.Fatalf("first fragment: %+v", h)
	}
	binary.BigEndian.PutUint16(pkt[6:], 1208/8) // the rest
	h, _ = Parse(pkt)
	if !h.Fragment() || h.FragOffset != 1208 || h.MoreFragments || h.DstPort != 0 {
		t.Fatalf("second fragment: %+v", h)
	}
	if ClampMSS(h, pkt, 1190) {
		t.Fatal("a fragment has no TCP header to change")
	}
}
