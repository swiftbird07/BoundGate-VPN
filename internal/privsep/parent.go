//go:build linux

package privsep

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/anchors"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// Parent answers one worker. Everything a worker asks for is checked here:
// this is where a compromised worker meets the machine.
type Parent struct {
	Key devicekey.DeviceKey
	// Net is the host's configurator (with its cleanup journal).
	Net netcfg.Configurator
	// Config is handed to the worker as it is.
	Config []byte
	// TUNName is the one device the worker may create; the changes it asks
	// for are for the device that became (utun names itself on a Mac).
	TUNName   string
	WorkerUID int
	// Anchors is what the node trusts across restarts. The parent is its
	// only writer, and changes it by its own rules (internal/anchors).
	Anchors anchors.Anchors
	Log     *slog.Logger

	mu  sync.Mutex
	dev string
	// a chain of admin key lists that is still arriving
	chain      []binding.SignedSet
	chainBytes int
}

// maxInFlight bounds the requests the parent works on at once: signatures
// (a TPM takes tens of milliseconds) and commands (ip, nft).
const maxInFlight = 16

// Serve answers the worker on conn until it closes or ctx ends.
func (p *Parent) Serve(ctx context.Context, conn *net.UnixConn) error {
	go func() {
		<-ctx.Done()
		_ = conn.SetReadDeadline(time.Now())
	}()
	sem := make(chan struct{}, maxInFlight)
	var wg sync.WaitGroup
	defer wg.Wait()
	buf := make([]byte, maxMessage)
	for {
		n, _, flags, _, err := conn.ReadMsgUnix(buf, nil)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if n == 0 {
			return nil // the worker closed its end
		}
		if flags&unix.MSG_TRUNC != 0 {
			return errors.New("privsep: the worker sent an oversized message")
		}
		var req request
		if err := json.Unmarshal(buf[:n], &req); err != nil {
			return fmt.Errorf("privsep: the worker sent a malformed message: %w", err)
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			result, fd, err := p.answer(ctx, req)
			resp := response{ID: req.ID}
			if err != nil {
				resp.Err = err.Error()
			} else if result != nil {
				resp.Result, _ = json.Marshal(result)
			}
			b, _ := json.Marshal(resp)
			var oob []byte
			if fd >= 0 {
				oob = unix.UnixRights(fd)
			}
			_, _, _ = conn.WriteMsgUnix(b, oob, nil)
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}()
	}
}

// answer is handle, and an error instead of the end of the service should
// handling what the worker sent ever panic: the parent reads bytes the
// worker chose (requests, signed lists, bindings), and it is the process
// that must stay.
func (p *Parent) answer(ctx context.Context, req request) (result any, fd int, err error) {
	defer func() {
		if r := recover(); r != nil {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
			p.Log.Error("privsep: a request of the worker made the parent panic", "op", req.Op, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			result, fd, err = nil, -1, fmt.Errorf("privsep: %s failed", req.Op)
		}
	}()
	return p.handle(ctx, req)
}

// refuse logs and returns a request the rules do not allow.
func (p *Parent) refuse(op, why string, attrs ...any) error {
	p.Log.Warn("privsep: refused a request of the worker", append([]any{"op", op, "reason", why}, attrs...)...)
	return fmt.Errorf("privsep: %s refused: %s", op, why)
}

// handle runs one request. fd >= 0 is a descriptor to pass along (and
// close afterwards).
func (p *Parent) handle(ctx context.Context, req request) (result any, fd int, err error) {
	fd = -1
	decode := func(v any) error {
		if err := json.Unmarshal(req.Args, v); err != nil {
			return p.refuse(req.Op, "malformed arguments")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	switch req.Op {
	case opHello:
		der, err := x509.MarshalPKIXPublicKey(p.Key.Public())
		if err != nil {
			return nil, fd, err
		}
		return Hello{Config: p.Config, PublicKey: der, KeyKind: p.Key.Kind(), HardwareBound: p.Key.HardwareBound(), WorkerUID: p.WorkerUID, ParentUID: os.Geteuid()}, fd, nil

	case opSign:
		var a signArgs
		if err := decode(&a); err != nil {
			return nil, fd, err
		}
		switch a.Hash {
		case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		default:
			return nil, fd, p.refuse(req.Op, "hash is not SHA-256/384/512")
		}
		if len(a.Digest) != a.Hash.Size() {
			return nil, fd, p.refuse(req.Op, "digest length does not match its hash")
		}
		sig, err := p.Key.Sign(rand.Reader, a.Digest, a.Hash)
		if err != nil {
			return nil, fd, err
		}
		return signResult{Signature: sig}, fd, nil

	case opCreateTUN:
		var a tunArgs
		if err := decode(&a); err != nil {
			return nil, fd, err
		}
		if a.Name != p.TUNName {
			return nil, fd, p.refuse(req.Op, "not the configured device", "name", a.Name)
		}
		if a.MTU < 576 || a.MTU > 65535 {
			return nil, fd, p.refuse(req.Op, "MTU out of range", "mtu", a.MTU)
		}
		dev, name, err := p.Net.CreateTUN(a.Name, a.MTU)
		if err != nil {
			return nil, fd, err
		}
		p.mu.Lock()
		p.dev = name
		p.mu.Unlock()
		// the worker gets its own descriptor; this one goes, and with the
		// worker's the device goes too
		defer dev.Close()
		f, ok := dev.(interface{ File() *os.File })
		if !ok {
			return nil, fd, errors.New("privsep: the device has no descriptor to pass on")
		}
		sc, err := f.File().SyscallConn()
		if err != nil {
			return nil, fd, err
		}
		var dupErr error
		if err := sc.Control(func(raw uintptr) { fd, dupErr = unix.Dup(int(raw)) }); err != nil {
			return nil, -1, err
		}
		if dupErr != nil {
			return nil, -1, dupErr
		}
		return tunResult{Name: name}, fd, nil

	case opSetAddress:
		var a addressArgs
		if err := decode(&a); err != nil {
			return nil, fd, err
		}
		if err := p.ownDevice(req.Op, a.Ifname); err != nil {
			return nil, fd, err
		}
		if !a.Addr.IsValid() || a.MTU < 576 || a.MTU > 65535 {
			return nil, fd, p.refuse(req.Op, "invalid address or MTU", "addr", a.Addr, "mtu", a.MTU)
		}
		return nil, fd, p.Net.SetAddress(ctx, a.Ifname, a.Addr, a.MTU)

	case opAddRoute, opDelRoute:
		var a routeArgs
		if err := decode(&a); err != nil {
			return nil, fd, err
		}
		if err := p.ownDevice(req.Op, a.Ifname); err != nil {
			return nil, fd, err
		}
		if !a.Dst.IsValid() || a.Dst != a.Dst.Masked() {
			return nil, fd, p.refuse(req.Op, "not a network prefix", "dst", a.Dst)
		}
		if req.Op == opAddRoute {
			return nil, fd, p.Net.AddRoute(ctx, a.Dst, a.Ifname)
		}
		return nil, fd, p.Net.DelRoute(ctx, a.Dst, a.Ifname)

	case opAddBypass, opDelBypass:
		var a hostArgs
		if err := decode(&a); err != nil {
			return nil, fd, err
		}
		// a host route to a control plane, hub or IdP: some unicast address
		h := a.Host
		if !h.IsValid() || h.IsUnspecified() || h.IsLoopback() || h.IsMulticast() || h.IsLinkLocalUnicast() || h.IsLinkLocalMulticast() {
			return nil, fd, p.refuse(req.Op, "not a unicast host address", "host", h)
		}
		if req.Op == opAddBypass {
			return nil, fd, p.Net.AddBypass(ctx, h)
		}
		return nil, fd, p.Net.DelBypass(ctx, h)

	case opEnableForwarding:
		return nil, fd, p.Net.EnableForwarding(ctx)

	case opAllowForward:
		var a switchArgs
		if err := decode(&a); err != nil {
			return nil, fd, err
		}
		if err := p.ownDevice(req.Op, a.Ifname); err != nil {
			return nil, fd, err
		}
		found, err := p.Net.AllowForward(ctx, a.Ifname, a.On)
		return foundResult{Found: found}, fd, err

	case opSetNAT:
		var a natArgs
		if err := decode(&a); err != nil {
			return nil, fd, err
		}
		if err := p.ownDevice(req.Op, a.Ifname); err != nil {
			return nil, fd, err
		}
		// the rule every node applies to a snapshot's pool
		if len(a.Dsts) > 0 && (a.Pool != a.Pool.Masked() || !registry.PrivatePool(a.Pool)) {
			return nil, fd, p.refuse(req.Op, "the pool is not an overlay pool (a private or shared range, at most /8)", "pool", a.Pool)
		}
		if len(a.Dsts) > 1024 {
			return nil, fd, p.refuse(req.Op, "too many destinations", "n", len(a.Dsts))
		}
		for _, d := range a.Dsts {
			if !d.IsValid() || d != d.Masked() {
				return nil, fd, p.refuse(req.Op, "a destination is not a network prefix", "dst", d)
			}
		}
		return nil, fd, p.Net.SetNAT(ctx, a.Pool, a.Dsts, a.Ifname)

	case opReplyViaArrival:
		var a switchArgs
		if err := decode(&a); err != nil {
			return nil, fd, err
		}
		if err := p.ownDevice(req.Op, a.Ifname); err != nil {
			return nil, fd, err
		}
		ar, ok := p.Net.(netcfg.ArrivalRouter)
		if !ok {
			return nil, fd, errors.New("privsep: this host cannot send replies the way they came")
		}
		return nil, fd, ar.ReplyViaArrival(ctx, a.Ifname, a.On)

	case opPinControl:
		var a pinArgs
		if err := decode(&a); err != nil {
			return nil, fd, err
		}
		if p.Anchors == nil {
			return nil, fd, p.refuse(req.Op, "no anchors")
		}
		h, err := devicekey.ParseSPKIHash(a.SPKI)
		if err != nil {
			return nil, fd, p.refuse(req.Op, "not a key's hash")
		}
		if cur, ok, _ := p.Anchors.Pin(); ok && cur == h {
			return nil, fd, nil
		}
		// the one moment that rests on trust: nothing is pinned, and what
		// is pinned now stays (control.pin in the configuration leaves none)
		if err := p.Anchors.SetPin(h); err != nil {
			return nil, fd, p.refuse(req.Op, err.Error(), "fingerprint", h.Fingerprint())
		}
		p.Log.Warn("privsep: pinned the control plane's key, on first use", "fingerprint", h.Fingerprint())
		return nil, fd, nil

	case opFollowSigners:
		var a followArgs
		if err := decode(&a); err != nil {
			return nil, fd, err
		}
		if p.Anchors == nil {
			return nil, fd, p.refuse(req.Op, "no anchors")
		}
		p.mu.Lock()
		for _, l := range a.Links {
			p.chainBytes += len(l.Set) + len(l.Signature)
		}
		p.chain = append(p.chain, a.Links...)
		if len(p.chain) > binding.MaxChain || p.chainBytes > maxChainBytes {
			n := len(p.chain)
			p.chain, p.chainBytes = nil, 0
			p.mu.Unlock()
			return nil, fd, p.refuse(req.Op, "the chain is too long", "links", n)
		}
		if a.More {
			p.mu.Unlock()
			return nil, fd, nil
		}
		chain := p.chain
		p.chain, p.chainBytes = nil, 0
		p.mu.Unlock()
		before, err := p.Anchors.Trust()
		if err != nil {
			return nil, fd, err
		}
		after, err := p.Anchors.Follow(chain)
		if err != nil {
			return nil, fd, p.refuse(req.Op, err.Error(), "pinned_version", before.Version)
		}
		if after.Hash != before.Hash {
			p.Log.Warn("privsep: the admin key list moved, by its signatures", "from", before.Version, "to", after.Version, "keys", len(after.Keys))
		}
		return followResult{Trust: after}, fd, nil

	case opRecord:
		var a recordArgs
		if err := decode(&a); err != nil {
			return nil, fd, err
		}
		if p.Anchors == nil {
			return nil, fd, p.refuse(req.Op, "no anchors")
		}
		if err := p.Anchors.Record(a.Evidence); err != nil {
			return nil, fd, p.refuse(req.Op, err.Error())
		}
		return nil, fd, nil
	}
	return nil, fd, p.refuse(req.Op, "unknown operation")
}

// ownDevice: every change of the host's network is about the node's own
// device, never another interface of the machine.
func (p *Parent) ownDevice(op, ifname string) error {
	p.mu.Lock()
	dev := p.dev
	p.mu.Unlock()
	if ifname == "" || ifname != dev {
		return p.refuse(op, "not the node's device", "ifname", ifname)
	}
	return nil
}
