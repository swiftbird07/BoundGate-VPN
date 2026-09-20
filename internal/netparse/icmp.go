package netparse

import "encoding/binary"

// FragNeeded builds the ICMP "fragmentation needed" answer (type 3, code 4,
// RFC 1191) to an IPv4 packet that does not fit a path of the given MTU: from
// the packet's destination back to its source, carrying the header and the
// first 8 payload bytes. Nil when pkt is not a plain IPv4 packet or is itself
// an ICMP error (those are never answered).
func FragNeeded(pkt []byte, mtu int) []byte {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return nil
	}
	if pkt[9] == 1 && len(pkt) > ihl {
		switch pkt[ihl] {
		case 0, 8, 13, 14: // echo and timestamp are queries, the rest are errors
		default:
			return nil
		}
	}
	quote := pkt[:min(len(pkt), ihl+8)]
	out := make([]byte, 20+8+len(quote))
	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	out[8] = 64
	out[9] = 1
	copy(out[12:16], pkt[16:20])
	copy(out[16:20], pkt[12:16])
	binary.BigEndian.PutUint16(out[10:], Checksum(out[:20], 0))
	icmp := out[20:]
	icmp[0], icmp[1] = 3, 4
	binary.BigEndian.PutUint16(icmp[6:], uint16(mtu))
	copy(icmp[8:], quote)
	binary.BigEndian.PutUint16(icmp[2:], Checksum(icmp, 0))
	return out
}
