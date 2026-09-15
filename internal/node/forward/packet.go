// Package forward is the node data path below the policy layer: packet
// buffer conventions and the table that maps destinations to tunnels.
// Nothing here decides *whether* a packet may pass; that is the hub
// service's job (and the ACL's from M3). This package only moves packets it
// is handed.
package forward

// Offset is the number of spare bytes kept in front of every packet buffer.
// The tun package needs room for a virtio header on Linux (10 bytes) and the
// address-family word on macOS (4 bytes); 16 covers both.
const Offset = 16

// MaxPacket is the largest packet the TUN reader can hand us (GSO-coalesced
// on Linux).
const MaxPacket = 65535

// PacketWriter is one end of a tunnel as the table sees it. Both server
// tunnels (transport.Tunnel) and client tunnels (transport.ClientTunnel)
// implement it.
type PacketWriter interface {
	// WritePacket sends one IP packet. A non-nil icmp return is an ICMP
	// error to deliver back towards the original sender.
	WritePacket(b []byte) (icmp []byte, err error)
}
