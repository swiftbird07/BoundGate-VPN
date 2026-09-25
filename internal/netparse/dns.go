package netparse

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"time"
)

// maxDNSAnswers bounds what one response may teach: a name with more
// addresses than this is read up to here and no further.
const maxDNSAnswers = 64

// DNSQueryName returns the lower-cased name of the question in a DNS query
// message (UDP payload). Responses and malformed messages yield ok=false.
// Compression pointers are not followed in a question name.
func DNSQueryName(payload []byte) (string, bool) {
	_, name, ok := DNSQuery(payload)
	return name, ok
}

// DNSQuery reads a standard query the way a stub resolver sends it: one
// question, no answer or authority records, at most one additional record
// (the EDNS OPT). It returns the message ID and the lower-cased question
// name. Anything else yields ok=false: a flow that a permit opened for a
// question must carry questions, not other data to port 53.
func DNSQuery(payload []byte) (id uint16, name string, ok bool) {
	if len(payload) < 12 {
		return 0, "", false
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 != 0 || flags&0x7800 != 0 { // QR: a response; OPCODE: not a query
		return 0, "", false
	}
	if binary.BigEndian.Uint16(payload[4:6]) != 1 || // QDCOUNT
		binary.BigEndian.Uint16(payload[6:8]) != 0 || // ANCOUNT
		binary.BigEndian.Uint16(payload[8:10]) != 0 || // NSCOUNT
		binary.BigEndian.Uint16(payload[10:12]) > 1 { // ARCOUNT
		return 0, "", false
	}
	name, _, ok = questionName(payload)
	return binary.BigEndian.Uint16(payload[0:2]), name, ok
}

// DNSResponseID returns the message ID of a DNS response (QR set).
func DNSResponseID(payload []byte) (uint16, bool) {
	if len(payload) < 12 || binary.BigEndian.Uint16(payload[2:4])&0x8000 == 0 {
		return 0, false
	}
	return binary.BigEndian.Uint16(payload[0:2]), true
}

// DNSAnswer reads a DNS response: the name of its question, the addresses
// its A and AAAA records answer with, and the smallest time to live among
// them. A message that is not a response, answers with an error, carries no
// address or cannot be read yields ok=false. The answer's own name is not
// looked at: a CNAME chain ends in records whose addresses belong to the
// question, which is the name the asking device used.
func DNSAnswer(payload []byte) (name string, addrs []netip.Addr, ttl time.Duration, ok bool) {
	if len(payload) < 12 {
		return "", nil, 0, false
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 == 0 { // QR: query
		return "", nil, 0, false
	}
	if flags&0x000f != 0 { // RCODE: no name, no addresses
		return "", nil, 0, false
	}
	if flags&0x0200 != 0 { // TC: the rest is only in the TCP answer
		return "", nil, 0, false
	}
	if binary.BigEndian.Uint16(payload[4:6]) != 1 { // QDCOUNT
		return "", nil, 0, false // one question per message, as every resolver sends it
	}
	count := min(int(binary.BigEndian.Uint16(payload[6:8])), maxDNSAnswers) // ANCOUNT
	name, off, ok := questionName(payload)
	if !ok {
		return "", nil, 0, false
	}
	off += 4 // QTYPE, QCLASS
	var least uint32 = ^uint32(0)
	for i := 0; i < count; i++ {
		var ok bool
		if off, ok = skipName(payload, off); !ok {
			break
		}
		if off+10 > len(payload) {
			break
		}
		typ := binary.BigEndian.Uint16(payload[off : off+2])
		class := binary.BigEndian.Uint16(payload[off+2 : off+4])
		rrTTL := binary.BigEndian.Uint32(payload[off+4 : off+8])
		n := int(binary.BigEndian.Uint16(payload[off+8 : off+10]))
		off += 10
		if off+n > len(payload) {
			break
		}
		if class == 1 { // IN
			var a netip.Addr
			switch {
			case typ == 1 && n == 4:
				a = netip.AddrFrom4([4]byte(payload[off : off+4]))
			case typ == 28 && n == 16:
				a = netip.AddrFrom16([16]byte(payload[off : off+16]))
			}
			if a.IsValid() {
				addrs = append(addrs, a)
				least = min(least, rrTTL)
			}
		}
		off += n
	}
	if len(addrs) == 0 {
		return "", nil, 0, false
	}
	return name, addrs, time.Duration(least) * time.Second, true
}

// questionName reads the name of the first question and returns the offset
// behind it. A question name carries no compression pointer.
func questionName(payload []byte) (string, int, bool) {
	if binary.BigEndian.Uint16(payload[4:6]) == 0 { // QDCOUNT
		return "", 0, false
	}
	var sb strings.Builder
	off := 12
	for {
		if off >= len(payload) {
			return "", 0, false
		}
		l := int(payload[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || off+l > len(payload) || sb.Len()+l+1 > 253 {
			return "", 0, false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for _, c := range payload[off : off+l] {
			// a dot inside a label would read as a label boundary: the
			// name on the wire is another than the one a list sees
			if c < 0x21 || c > 0x7e || c == '.' {
				return "", 0, false
			}
			sb.WriteByte(c)
		}
		off += l
	}
	if sb.Len() == 0 || off+4 > len(payload) {
		return "", 0, false
	}
	return strings.ToLower(sb.String()), off, true
}

// skipName steps over the name of a resource record, which may end in a
// compression pointer. The pointer itself is not followed: a record's own
// name says nothing this code uses.
func skipName(payload []byte, off int) (int, bool) {
	for {
		if off >= len(payload) {
			return 0, false
		}
		l := int(payload[off])
		switch {
		case l == 0:
			return off + 1, true
		case l&0xc0 == 0xc0:
			if off+2 > len(payload) {
				return 0, false
			}
			return off + 2, true
		case l&0xc0 != 0:
			return 0, false
		}
		off += 1 + l
	}
}
