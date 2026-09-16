package netparse

import (
	"encoding/binary"
)

// TCPReset builds the two RST segments that abort the TCP connection a
// packet belongs to: toSender goes back to the packet's source (as if the
// destination refused), toReceiver continues in the packet's direction (so
// the destination frees its half of the connection). IPv4 only; both are
// nil when pkt is not an IPv4 TCP segment.
func TCPReset(pkt []byte) (toSender, toReceiver []byte) {
	h, ok := Parse(pkt)
	if !ok || h.Version != 4 || h.Proto != ProtoTCP || h.Payload < 0 {
		return nil, nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	tcp := pkt[ihl:]
	seq := binary.BigEndian.Uint32(tcp[4:8])
	ack := binary.BigEndian.Uint32(tcp[8:12])
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total > len(pkt) {
		total = len(pkt)
	}
	payloadLen := uint32(total - h.Payload)
	if payloadLen > uint32(total) {
		payloadLen = 0
	}
	if h.TCPFlags&TCPSyn != 0 {
		payloadLen++
	}
	if h.TCPFlags&TCPFin != 0 {
		payloadLen++
	}
	// Towards the sender: SEQ = its ACK (what it expects next), and
	// acknowledge everything it sent so the RST is in its window.
	if h.TCPFlags&TCPAck != 0 {
		toSender = buildRST(h.Dst.As4(), h.Src.As4(), h.DstPort, h.SrcPort, ack, seq+payloadLen, TCPRst|TCPAck)
	} else {
		toSender = buildRST(h.Dst.As4(), h.Src.As4(), h.DstPort, h.SrcPort, 0, seq+payloadLen, TCPRst|TCPAck)
	}
	// Towards the receiver: the sender's own SEQ is exactly what the
	// receiver expects next.
	toReceiver = buildRST(h.Src.As4(), h.Dst.As4(), h.SrcPort, h.DstPort, seq, 0, TCPRst)
	return toSender, toReceiver
}

func buildRST(src, dst [4]byte, sport, dport uint16, seq, ack uint32, flags uint8) []byte {
	b := make([]byte, 40)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], 40)
	binary.BigEndian.PutUint16(b[4:6], 0)
	binary.BigEndian.PutUint16(b[6:8], 0x4000) // DF
	b[8] = 64
	b[9] = ProtoTCP
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	binary.BigEndian.PutUint16(b[10:12], Checksum(b[:20], 0))
	t := b[20:]
	binary.BigEndian.PutUint16(t[0:2], sport)
	binary.BigEndian.PutUint16(t[2:4], dport)
	binary.BigEndian.PutUint32(t[4:8], seq)
	binary.BigEndian.PutUint32(t[8:12], ack)
	t[12] = 5 << 4
	t[13] = flags
	binary.BigEndian.PutUint16(t[14:16], 0) // window
	// pseudo header: src, dst, zero, proto, tcp length
	var ph [12]byte
	copy(ph[0:4], src[:])
	copy(ph[4:8], dst[:])
	ph[9] = ProtoTCP
	binary.BigEndian.PutUint16(ph[10:12], 20)
	binary.BigEndian.PutUint16(t[16:18], Checksum(t, ^Checksum(ph[:], 0)))
	return b
}

// Checksum computes the Internet checksum of b starting from the running
// ones-complement sum initial (0 for a fresh computation; to chain, pass
// the complement of a previous result).
func Checksum(b []byte, initial uint16) uint16 {
	sum := uint32(initial)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
