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
// The parent also keeps what the node trusts from one start to the next
// (internal/anchors): the control plane's pin, the admin key list, the
// binding history. The worker reads them and asks for changes, which the
// parent makes by rules that need no trust in the worker: a pin only while
// there is none, a list only along signed links, history only with the
// signature that proves it. What a worker was made to believe ends with it.
//
// The messages are JSON, one per SOCK_SEQPACKET datagram; the TUN device
// travels as a file descriptor (SCM_RIGHTS). Linux only for now: a Mac has
// no SOCK_SEQPACKET for local sockets.
package privsep

import (
	"crypto"
	"encoding/json"
	"net/netip"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/anchors"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
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
	opPinControl       = "pin_control"
	opFollowSigners    = "follow_signers"
	opRecord           = "record"
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
	// ParentUID is whose files the anchors are: the worker reads them only
	// as that user's.
	ParentUID int `json:"parent_uid"`
}

type pinArgs struct {
	SPKI string `json:"spki"` // hex
}

// followArgs carries a chain of admin key lists, in pieces: a chain is
// longer than a message may be. The parent verifies it when the last piece
// (More false) is there.
type followArgs struct {
	Links []binding.SignedSet `json:"links"`
	More  bool                `json:"more,omitempty"`
}

type followResult struct {
	Trust binding.Trust `json:"trust"`
}

type recordArgs struct {
	Evidence []anchors.Evidence `json:"evidence"`
}

// What a chain in pieces may grow to before the parent drops it.
const (
	maxChainBytes = 16 << 20
	pieceBytes    = 24 << 10
)

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
