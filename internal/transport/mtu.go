package transport

import "gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"

// FitMTU is the largest IP packet that fits a QUIC datagram on every
// connection, however small its packets stay. QUIC packets start at 1280
// bytes and only grow by path MTU discovery, which quic-go does on a real UDP
// socket alone: a server behind boundgate-mux hands it an encapsulating
// PacketConn and never grows. quic-go then takes 1243 bytes per DATAGRAM
// payload (1280 - type byte - 20 connection ID - 16 tag); the HTTP datagram
// prefix (quarter stream ID, context ID) takes up to 3 more. 1230 leaves a
// margin and is the default MTU of the tunnel device (internal/node).
const FitMTU = 1230

// tooLarge corrects the answer to a packet that did not fit. connect-ip-go
// answers with "packet too big, MTU 1280", the IPv6 minimum, also to an IPv4
// packet of 1280 bytes: the sender learns nothing, repeats the packet, and the
// connection stalls as soon as it carries data (what a hub behind a mux did
// to every download). For IPv4 the answer becomes "fragmentation needed" with
// a size that does fit.
func tooLarge(pkt, icmp []byte) []byte {
	if icmp == nil || len(pkt) == 0 || pkt[0]>>4 != 4 {
		return icmp
	}
	return netparse.FragNeeded(pkt, FitMTU)
}
