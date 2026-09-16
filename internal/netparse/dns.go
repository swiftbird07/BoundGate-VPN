package netparse

import (
	"encoding/binary"
	"strings"
)

// DNSQueryName returns the lower-cased name of the first question in a DNS
// query message (UDP payload). Responses and malformed messages yield
// ok=false. Compression pointers are not followed in a question name.
func DNSQueryName(payload []byte) (string, bool) {
	if len(payload) < 12 {
		return "", false
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 != 0 { // QR: response
		return "", false
	}
	if binary.BigEndian.Uint16(payload[4:6]) == 0 { // QDCOUNT
		return "", false
	}
	var sb strings.Builder
	off := 12
	for {
		if off >= len(payload) {
			return "", false
		}
		l := int(payload[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || off+l > len(payload) || sb.Len()+l+1 > 253 {
			return "", false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for _, c := range payload[off : off+l] {
			if c < 0x21 || c > 0x7e {
				return "", false
			}
			sb.WriteByte(c)
		}
		off += l
	}
	if sb.Len() == 0 || off+4 > len(payload) {
		return "", false
	}
	return strings.ToLower(sb.String()), true
}
