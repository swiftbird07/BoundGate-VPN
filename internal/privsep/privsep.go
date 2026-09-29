// Package privsep splits boundgate-node into two processes
// (docs/PRIVSEP.md). The parent keeps what needs root: the device key, the
// host's network configuration (TUN device, routes, forwarding, NAT) and
// the local socket's place in the file system. The worker runs everything
// else as an unprivileged user: the control channel, the tunnels, every
// packet and its parsers, the ACL. It asks the parent over a socket pair
// for a signature or a network change, and the parent answers only what
// its rules allow. Code execution in the worker therefore reaches neither
// the key nor more of the host's network than the node's own device.
//
// The messages are JSON, one per SOCK_SEQPACKET datagram; the TUN device
// travels as a file descriptor (SCM_RIGHTS). Linux only for now: a Mac has
// no SOCK_SEQPACKET for local sockets.
package privsep

import (
	"crypto"
	"encoding/json"
	"net/netip"
)

// Ops the worker may ask for.
const (
	opHello            = "hello"
	opSign             = "sign"
	opCreateTUN        = "create_tun"
	opSetAddress       = "set_address"
	opAddRoute         = "add_route"
	opDelRoute         = "del_route"
	opAddBypass        = "add_bypass"
	opDelBypass        = "del_bypass"
	opEnableForwarding = "enable_forwarding"
	opAllowForward     = "allow_forward"
	opSetNAT           = "set_nat"
	opReplyViaArrival  = "reply_via_arrival"
)

// maxMessage bounds one datagram in either direction.
const maxMessage = 64 << 10

type request struct {
	ID   uint64          `json:"id"`
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args,omitempty"`
}

type response struct {
	ID     uint64          `json:"id"`
	Err    string          `json:"err,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// Hello is what the worker starts with: its configuration (the parent read
// the file, which the worker may not be able to) and the public half of the
// device key.
type Hello struct {
	Config        []byte `json:"config"`
	PublicKey     []byte `json:"public_key"` // PKIX DER
	KeyKind       string `json:"key_kind"`
	HardwareBound bool   `json:"hardware_bound"`
	// WorkerUID is who the worker runs as, for its status.
	WorkerUID int `json:"worker_uid"`
}

type signArgs struct {
	Digest []byte      `json:"digest"`
	Hash   crypto.Hash `json:"hash"`
}

type signResult struct {
	Signature []byte `json:"signature"`
}

type tunArgs struct {
	Name string `json:"name"`
	MTU  int    `json:"mtu"`
}

type tunResult struct {
	Name string `json:"name"`
}

type addressArgs struct {
	Ifname string       `json:"ifname"`
	Addr   netip.Prefix `json:"addr"`
	MTU    int          `json:"mtu"`
}

type routeArgs struct {
	Dst    netip.Prefix `json:"dst"`
	Ifname string       `json:"ifname"`
}

type hostArgs struct {
	Host netip.Addr `json:"host"`
}

type switchArgs struct {
	Ifname string `json:"ifname"`
	On     bool   `json:"on"`
}

type foundResult struct {
	Found bool `json:"found"`
}

type natArgs struct {
	Pool   netip.Prefix   `json:"pool"`
	Dsts   []netip.Prefix `json:"dsts"`
	Ifname string         `json:"ifname"`
}
