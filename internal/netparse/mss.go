package netparse

import "encoding/binary"

// ClampMSS lowers the maximum segment size that a TCP SYN or SYN-ACK
// announces to at most mss, in place, and reports whether it changed the
// packet. Both ends of a TCP connection through a tunnel then send segments
// that fit it, whatever MTU their own interfaces have and whether or not
// path MTU discovery works between them: a peer that sends without the DF
// bit gets its packets fragmented instead of an ICMP answer, and an ICMP
// answer does not always arrive. A SYN without the option announces 536 and
// is left alone. h must be the parsed header of pkt.
func ClampMSS(h Header, pkt []byte, mss uint16) bool {
	if h.Proto != ProtoTCP || h.TCPFlags&TCPSyn == 0 || h.Fragment() || h.Payload < 0 || h.Payload > len(pkt) {
		return false
	}
	var l4 int
	switch h.Version {
	case 4:
		l4 = int(pkt[0]&0x0f) * 4
	case 6:
		l4 = 40
	default:
		return false
	}
	opts := pkt[l4+20 : h.Payload]
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 0 { // end of options
			return false
		}
		if kind == 1 { // no-op
			i++
			continue
		}
		if i+1 >= len(opts) || opts[i+1] < 2 || i+int(opts[i+1]) > len(opts) {
			return false
		}
		if kind == 2 && opts[i+1] == 4 {
			old := binary.BigEndian.Uint16(opts[i+2:])
			if old <= mss {
				return false
			}
			binary.BigEndian.PutUint16(opts[i+2:], mss)
			// RFC 1624: HC' = ~(~HC + ~m + m'); the option starts at an even
			// offset or not, the checksum words are aligned to the segment
			sum := pkt[l4+16 : l4+18]
			at := l4 + 20 + i + 2
			if (at-l4)%2 == 0 {
				fixChecksum(sum, old, mss)
			} else {
				// the two bytes straddle two checksum words
				lo, hi := pkt[at-1], pkt[at+2]
				fixChecksum(sum, uint16(lo)<<8|old>>8, uint16(lo)<<8|mss>>8)
				fixChecksum(sum, old<<8|uint16(hi), mss<<8|uint16(hi))
			}
			return true
		}
		i += int(opts[i+1])
	}
	return false
}

func fixChecksum(sum []byte, old, new uint16) {
	c := uint32(^binary.BigEndian.Uint16(sum)) + uint32(^old) + uint32(new)
	c = c&0xffff + c>>16
	c = c&0xffff + c>>16
	binary.BigEndian.PutUint16(sum, ^uint16(c))
}
