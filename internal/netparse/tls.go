package netparse

import (
	"encoding/binary"
	"strings"
)

// SNIResult is the outcome of looking for a server name in TCP payload.
type SNIResult int

const (
	// SNINotTLS: the payload does not start a TLS ClientHello; stop looking.
	SNINotTLS SNIResult = iota
	// SNIFound: a server name was found.
	SNIFound
	// SNINone: a complete ClientHello without a server_name extension.
	SNINone
	// SNINeedMore: the ClientHello continues in a later segment; call again
	// with more payload appended.
	SNINeedMore
)

// MaxClientHello bounds how much payload a caller should buffer while
// waiting for the rest of a ClientHello (post-quantum key shares make
// ClientHellos larger than one 1280-byte segment).
const MaxClientHello = 16 << 10

// ClientHelloSNI extracts the server_name of a TLS ClientHello that starts
// at the beginning of payload. It never panics on malformed input.
func ClientHelloSNI(payload []byte) (string, SNIResult) {
	// TLS record: type(1) version(2) length(2)
	if len(payload) < 5 {
		if len(payload) > 0 && payload[0] != 0x16 {
			return "", SNINotTLS
		}
		return "", SNINeedMore
	}
	if payload[0] != 0x16 || payload[1] != 0x03 {
		return "", SNINotTLS
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recLen > MaxClientHello {
		return "", SNINotTLS
	}
	// handshake header: type(1) length(3)
	if len(payload) < 9 {
		return "", SNINeedMore
	}
	if payload[5] != 0x01 {
		return "", SNINotTLS
	}
	hsLen := int(payload[6])<<16 | int(payload[7])<<8 | int(payload[8])
	if hsLen > MaxClientHello {
		return "", SNINotTLS
	}
	// The ClientHello may span several records in theory; in practice it is
	// one record. Treat the handshake body as everything after the header
	// up to hsLen bytes, ignoring record boundaries beyond the first.
	body := payload[9:]
	if len(body) < hsLen {
		// try with what we have: the server_name extension is usually early
		if name, res := parseClientHello(body, false); res == SNIFound {
			return name, res
		}
		return "", SNINeedMore
	}
	return parseClientHello(body[:hsLen], true)
}

// parseClientHello walks the ClientHello body. complete says whether body
// is the whole message; a truncated body yields NeedMore when the name was
// not reached.
func parseClientHello(b []byte, complete bool) (string, SNIResult) {
	need := func(n int) bool { return len(b) >= n }
	truncated := func() (string, SNIResult) {
		if complete {
			return "", SNINotTLS
		}
		return "", SNINeedMore
	}
	if !need(2 + 32 + 1) {
		return truncated()
	}
	if b[0] != 0x03 { // legacy_version 3.x
		return "", SNINotTLS
	}
	off := 2 + 32
	sidLen := int(b[off])
	off += 1 + sidLen
	if !need(off + 2) {
		return truncated()
	}
	csLen := int(binary.BigEndian.Uint16(b[off:]))
	off += 2 + csLen
	if !need(off + 1) {
		return truncated()
	}
	cmLen := int(b[off])
	off += 1 + cmLen
	if !need(off + 2) {
		if complete {
			return "", SNINone // no extensions at all
		}
		return "", SNINeedMore
	}
	extLen := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	end := off + extLen
	for off+4 <= len(b) && off < end {
		typ := binary.BigEndian.Uint16(b[off:])
		l := int(binary.BigEndian.Uint16(b[off+2:]))
		off += 4
		if typ == 0 { // server_name
			if off+l > len(b) {
				return truncated()
			}
			return parseServerName(b[off : off+l])
		}
		off += l
	}
	if off >= end && end <= len(b) {
		return "", SNINone
	}
	return truncated()
}

func parseServerName(b []byte) (string, SNIResult) {
	if len(b) < 2 {
		return "", SNINotTLS
	}
	listLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if listLen > len(b) {
		return "", SNINotTLS
	}
	for len(b) >= 3 {
		typ := b[0]
		l := int(binary.BigEndian.Uint16(b[1:]))
		b = b[3:]
		if l > len(b) {
			return "", SNINotTLS
		}
		if typ == 0 {
			name := string(b[:l])
			if name == "" || len(name) > 253 || !validHostname(name) {
				return "", SNINotTLS
			}
			return strings.ToLower(name), SNIFound
		}
		b = b[l:]
	}
	return "", SNINone
}

func validHostname(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	return true
}
