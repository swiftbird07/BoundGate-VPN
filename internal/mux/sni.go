package mux

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// This file reads the TLS server name out of the first bytes a client
// sends: a TLS ClientHello on TCP, or the ClientHello inside the CRYPTO
// frames of a QUIC Initial packet on UDP. Initial packets are encrypted with
// keys everybody can derive from the packet itself (RFC 9001 §5.2); that is
// obfuscation, not secrecy, and exactly what lets a front end route QUIC by
// name without holding any key of the servers behind it.
//
// Everything here handles unauthenticated input from the internet: bounds
// are checked, nothing allocates proportionally to a length field, and every
// failure is just "no name".

var (
	errShort    = errors.New("mux: truncated")
	errNotQUIC  = errors.New("mux: not a QUIC long-header packet of a known version")
	errNoName   = errors.New("mux: no server name")
	errNeedMore = errors.New("mux: ClientHello incomplete")
)

// clientHelloSNI parses a TLS handshake message stream starting at a
// ClientHello. errNeedMore means the data ended before the server_name
// extension could be read.
func clientHelloSNI(b []byte) (string, error) {
	if len(b) < 4 {
		return "", errNeedMore
	}
	if b[0] != 1 { // handshake type client_hello
		return "", errNoName
	}
	n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n > 1<<16 {
		return "", errNoName
	}
	complete := len(b)-4 >= n
	body := b[4:]
	if complete {
		body = body[:n]
	}
	short := func() (string, error) {
		if complete {
			return "", errNoName
		}
		return "", errNeedMore
	}
	// legacy_version(2) random(32)
	if len(body) < 34 {
		return short()
	}
	p := body[34:]
	skip := func(lenBytes int) bool {
		if len(p) < lenBytes {
			return false
		}
		l := 0
		for i := 0; i < lenBytes; i++ {
			l = l<<8 | int(p[i])
		}
		if len(p) < lenBytes+l {
			return false
		}
		p = p[lenBytes+l:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression methods
		return short()
	}
	if len(p) < 2 {
		return short()
	}
	extLen := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) > extLen {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		typ := binary.BigEndian.Uint16(p)
		l := int(binary.BigEndian.Uint16(p[2:]))
		if len(p) < 4+l {
			return short()
		}
		ext := p[4 : 4+l]
		p = p[4+l:]
		if typ != 0 {
			continue
		}
		// server_name: list length(2), then entries type(1) length(2) name
		if len(ext) < 2 {
			return "", errNoName
		}
		ext = ext[2:]
		for len(ext) >= 3 {
			nl := int(binary.BigEndian.Uint16(ext[1:]))
			if len(ext) < 3+nl {
				return "", errNoName
			}
			if ext[0] == 0 {
				return validName(string(ext[3 : 3+nl]))
			}
			ext = ext[3+nl:]
		}
		return "", errNoName
	}
	return short()
}

func validName(s string) (string, error) {
	if len(s) == 0 || len(s) > 253 {
		return "", errNoName
	}
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return "", errNoName
		}
		out[i] = c
	}
	return string(out), nil
}

// readTLSClientHello reads TLS records from r until the ClientHello is
// complete enough to yield the server name. It returns the name and every
// byte it consumed, which the caller replays to the backend.
func readTLSClientHello(r io.Reader, max int) (string, []byte, error) {
	var raw, hs []byte
	hdr := make([]byte, 5)
	for len(raw) < max {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return "", raw, err
		}
		raw = append(raw, hdr...)
		n := int(binary.BigEndian.Uint16(hdr[3:]))
		if hdr[0] != 22 || n == 0 || n > 16384+256 || len(raw)+n > max {
			return "", raw, errNoName
		}
		rec := make([]byte, n)
		if _, err := io.ReadFull(r, rec); err != nil {
			return "", append(raw, rec...), err
		}
		raw = append(raw, rec...)
		hs = append(hs, rec...)
		name, err := clientHelloSNI(hs)
		if err == nil {
			return name, raw, nil
		}
		if !errors.Is(err, errNeedMore) {
			return "", raw, err
		}
	}
	return "", raw, errNoName
}

// --- QUIC ---

const (
	quicV1 = 0x00000001
	quicV2 = 0x6b3343cf
)

var (
	saltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	saltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

// longHeader is what the mux needs from a long-header packet.
type longHeader struct {
	version   uint32
	initial   bool
	dcid      []byte
	pnOffset  int // offset of the (protected) packet number; Initial only
	packetEnd int // end of this packet within the datagram; Initial only
}

func varint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	l := 1 << (b[0] >> 6)
	if len(b) < l {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < l; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, l
}

// parseLongHeader parses the invariant part of a long-header packet and,
// for Initial packets of QUIC v1/v2, the rest of the header.
func parseLongHeader(b []byte) (longHeader, error) {
	var h longHeader
	if len(b) < 7 || b[0]&0x80 == 0 {
		return h, errNotQUIC
	}
	h.version = binary.BigEndian.Uint32(b[1:5])
	p := 5
	dl := int(b[p])
	p++
	if dl > 20 || len(b) < p+dl+1 {
		return h, errShort
	}
	h.dcid = b[p : p+dl]
	p += dl
	sl := int(b[p])
	p++
	if sl > 20 || len(b) < p+sl {
		return h, errShort
	}
	p += sl
	typ := (b[0] >> 4) & 3
	switch h.version {
	case quicV1:
		h.initial = typ == 0
	case quicV2:
		h.initial = typ == 1
	default:
		return h, nil // version negotiation is the backend's business
	}
	if !h.initial {
		return h, nil
	}
	tl, n := varint(b[p:])
	if n == 0 || tl > uint64(len(b)) {
		return h, errShort
	}
	p += n + int(tl)
	if p > len(b) {
		return h, errShort
	}
	length, n := varint(b[p:])
	if n == 0 {
		return h, errShort
	}
	p += n
	if length < 20 || uint64(p)+length > uint64(len(b)) {
		return h, errShort
	}
	h.pnOffset, h.packetEnd = p, p+int(length)
	return h, nil
}

func expandLabel(secret []byte, label string, n int) []byte {
	info := make([]byte, 0, 4+6+len(label))
	info = append(info, byte(n>>8), byte(n), byte(6+len(label)))
	info = append(info, "tls13 "...)
	info = append(info, label...)
	info = append(info, 0)
	out := make([]byte, n)
	_, _ = io.ReadFull(hkdf.Expand(sha256.New, secret, info), out)
	return out
}

// openInitial removes the protection of a client Initial packet and returns
// its frames. It fails for Initials whose DCID field is not the client's
// original one (later in the handshake), which is how the mux tells them
// apart.
func openInitial(b []byte, h longHeader) ([]byte, error) {
	salt, keyL, ivL, hpL := saltV1, "quic key", "quic iv", "quic hp"
	if h.version == quicV2 {
		salt, keyL, ivL, hpL = saltV2, "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	initial := hkdf.Extract(sha256.New, h.dcid, salt)
	client := expandLabel(initial, "client in", 32)
	key, iv, hp := expandLabel(client, keyL, 16), expandLabel(client, ivL, 12), expandLabel(client, hpL, 16)

	if h.pnOffset+4+16 > h.packetEnd {
		return nil, errShort
	}
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], b[h.pnOffset+4:h.pnOffset+20])
	first := b[0] ^ (mask[0] & 0x0f)
	pnLen := int(first&3) + 1
	hdr := make([]byte, h.pnOffset+pnLen)
	copy(hdr, b[:h.pnOffset+pnLen])
	hdr[0] = first
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[h.pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[h.pnOffset+i])
	}
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, b[h.pnOffset+pnLen:h.packetEnd], hdr)
}

// cryptoFrames collects the CRYPTO frames of an Initial payload into dst
// (a reassembly buffer indexed by stream offset, capped).
func cryptoFrames(payload []byte, dst *cryptoBuf) error {
	p := payload
	for len(p) > 0 {
		t := p[0]
		switch {
		case t == 0x00 || t == 0x01: // PADDING, PING
			p = p[1:]
		case t == 0x02 || t == 0x03: // ACK
			p = p[1:]
			var f [4]uint64
			for i := range f {
				v, n := varint(p)
				if n == 0 {
					return errShort
				}
				f[i], p = v, p[n:]
			}
			if f[2] > 256 {
				return errShort
			}
			extra := int(f[2]) * 2
			if t == 0x03 {
				extra += 3
			}
			for i := 0; i < extra; i++ {
				_, n := varint(p)
				if n == 0 {
					return errShort
				}
				p = p[n:]
			}
		case t == 0x06: // CRYPTO
			p = p[1:]
			off, n := varint(p)
			if n == 0 {
				return errShort
			}
			p = p[n:]
			l, n := varint(p)
			if n == 0 || l > uint64(len(p)-n) {
				return errShort
			}
			p = p[n:]
			dst.add(off, p[:l])
			p = p[l:]
		default: // CONNECTION_CLOSE or anything else: nothing more to learn
			return nil
		}
	}
	return nil
}

// cryptoBuf reassembles the start of the CRYPTO stream. A ClientHello with
// post-quantum key shares spans two Initial packets, and browsers scatter
// it on purpose; the server name sits within the first few kilobytes.
type cryptoBuf struct {
	data []byte
	have []bool
}

const cryptoBufMax = 8192

func (c *cryptoBuf) add(off uint64, b []byte) {
	if off >= cryptoBufMax {
		return
	}
	end := int(off) + len(b)
	if end > cryptoBufMax {
		end = cryptoBufMax
	}
	if end > len(c.data) {
		c.data = append(c.data, make([]byte, end-len(c.data))...)
		c.have = append(c.have, make([]bool, end-len(c.have))...)
	}
	copy(c.data[off:end], b)
	for i := int(off); i < end; i++ {
		c.have[i] = true
	}
}

// prefix is the contiguous data from offset 0.
func (c *cryptoBuf) prefix() []byte {
	n := 0
	for n < len(c.have) && c.have[n] {
		n++
	}
	return c.data[:n]
}
