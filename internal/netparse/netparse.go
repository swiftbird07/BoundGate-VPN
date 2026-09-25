// Package netparse contains allocation-free parsers for the packet headers
// the gateway needs: IP version, addresses, protocol and ports. It never
// panics on malformed input; every function returns ok=false instead.
//
// SNI and DNS parsing (M3) will be added here and fuzzed together with
// these functions.
package netparse

import (
	"encoding/binary"
	"net/netip"
)

// IP protocol numbers.
const (
	ProtoICMP   uint8 = 1
	ProtoTCP    uint8 = 6
	ProtoUDP    uint8 = 17
	ProtoICMPv6 uint8 = 58
)

// Version returns 4 or 6, or 0 for an empty/unknown packet.
func Version(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	switch b[0] >> 4 {
	case 4:
		return 4
	case 6:
		return 6
	}
	return 0
}

// Header is the parsed L3 (and, when present, L4 port) summary of a packet.
type Header struct {
	Version int
	Src     netip.Addr
	Dst     netip.Addr
	Proto   uint8
	SrcPort uint16 // 0 unless TCP/UDP with enough bytes
	DstPort uint16
	// Payload is the offset of the transport payload (after TCP/UDP header),
	// or -1 if unknown.
	Payload int
	// TCPFlags is the flags byte for TCP, 0 otherwise.
	TCPFlags uint8
	// IPv4 fragmentation: FragOffset is the offset of this fragment in
	// bytes (0 for a whole packet and for a first fragment), MoreFragments
	// the MF bit, FragID the identification that the fragments of one
	// packet share. A fragment with FragOffset > 0 has no transport header:
	// its ports are 0.
	FragOffset    int
	MoreFragments bool
	FragID        uint16
}

// Fragment reports whether the packet is a fragment other than the first.
func (h Header) Fragment() bool { return h.FragOffset > 0 }

// TCP flag bits.
const (
	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPAck = 0x10
)

// Parse extracts the header summary. ok is false when the packet is not a
// well-formed IPv4/IPv6 packet, and when its length field does not match
// the bytes it came in: whoever receives the packet reads only what the
// length says, so bytes behind it would be inspected here (a server name,
// a DNS question) and never arrive, and bytes missing would be decided
// unseen. IPv6 extension headers are not walked: the protocol is then the
// next-header value and ports stay 0.
func Parse(b []byte) (h Header, ok bool) { return parse(b, true) }

// ParseQuoted parses the packet an ICMP error quotes: a leading part of the
// original, so its length field may exceed what is there.
func ParseQuoted(b []byte) (h Header, ok bool) { return parse(b, false) }

func parse(b []byte, whole bool) (h Header, ok bool) {
	h.Payload = -1
	switch Version(b) {
	case 4:
		if len(b) < 20 {
			return h, false
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if ihl < 20 || total < ihl || len(b) < ihl || (whole && total != len(b)) {
			return h, false
		}
		h.Version = 4
		h.Src = netip.AddrFrom4([4]byte(b[12:16]))
		h.Dst = netip.AddrFrom4([4]byte(b[16:20]))
		h.Proto = b[9]
		// fragments other than the first carry no transport header
		ff := binary.BigEndian.Uint16(b[6:8])
		h.FragOffset = int(ff&0x1fff) * 8
		h.MoreFragments = ff&0x2000 != 0
		h.FragID = binary.BigEndian.Uint16(b[4:6])
		if h.FragOffset == 0 {
			parseL4(&h, b[ihl:], ihl)
		}
		return h, true
	case 6:
		if len(b) < 40 {
			return h, false
		}
		// a payload length of 0 with more bytes would be a jumbogram, which
		// no link of the overlay carries
		if whole && 40+int(binary.BigEndian.Uint16(b[4:6])) != len(b) {
			return h, false
		}
		h.Version = 6
		h.Src = netip.AddrFrom16([16]byte(b[8:24]))
		h.Dst = netip.AddrFrom16([16]byte(b[24:40]))
		h.Proto = b[6]
		parseL4(&h, b[40:], 40)
		return h, true
	}
	return h, false
}

func parseL4(h *Header, l4 []byte, off int) {
	switch h.Proto {
	case ProtoTCP:
		if len(l4) < 20 {
			return
		}
		h.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		h.DstPort = binary.BigEndian.Uint16(l4[2:4])
		h.TCPFlags = l4[13]
		doff := int(l4[12]>>4) * 4
		if doff >= 20 && len(l4) >= doff {
			h.Payload = off + doff
		}
	case ProtoUDP:
		if len(l4) < 8 {
			return
		}
		h.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		h.DstPort = binary.BigEndian.Uint16(l4[2:4])
		h.Payload = off + 8
	}
}
