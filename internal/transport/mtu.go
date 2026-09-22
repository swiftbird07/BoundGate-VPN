package transport

import "gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"

// FitMTU is the largest IP packet that fits a QUIC datagram on every tunnel,
// and the default MTU of the tunnel device (internal/node). It is the IPv6
// minimum, and applications count on it: QUIC stacks (Apple's, Google's)
// send 1250 bytes of UDP payload and more with DF set, and at 1230 the Mac's
// kernel dropped them before the tunnel, so Safari stalled on every large
// page over HTTP/3.
//
// QUIC packets only grow by path MTU discovery, which quic-go does on a real
// UDP socket alone: a server behind boundgate-mux never grows. So tunnels
// start at PacketSize instead of quic-go's 1280: 1340 bytes leave 1303 per
// DATAGRAM payload (type byte, 20 bytes connection ID, 16 tag), the HTTP
// datagram prefix takes up to 3 more. 1368 bytes on the wire fit PPPoE
// (1492), DS-Lite (1460), WireGuard (1420) and mobile networks; a path that
// cannot carry them fails the handshake, and transport "auto" goes to TCP.
const FitMTU = 1280

// PacketSize is the QUIC packet size of tunnels from the first packet on.
const PacketSize = 1340

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
