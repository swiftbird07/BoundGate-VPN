//go:build linux

package privsep

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/anchors"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
)

// Client is the worker's end: the device key and the host's network, both
// through the parent.
type Client struct {
	conn *net.UnixConn

	mu      sync.Mutex
	next    uint64
	pending map[uint64]chan reply
	err     error
	done    chan struct{}
}

type reply struct {
	resp response
	fd   int
}

// ErrParentGone: the parent closed the socket or died; the worker ends.
var ErrParentGone = errors.New("privsep: the privileged parent is gone")

// Dial takes the worker's end of the socket pair (inherited as f).
func Dial(f *os.File) (*Client, error) {
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("privsep: %w", err)
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, errors.New("privsep: descriptor is not a unix socket")
	}
	cl := &Client{conn: uc, pending: map[uint64]chan reply{}, done: make(chan struct{})}
	go cl.readLoop()
	return cl, nil
}

// Done is closed when the parent is gone.
func (c *Client) Done() <-chan struct{} { return c.done }

func (c *Client) readLoop() {
	buf := make([]byte, maxMessage)
	oob := make([]byte, unix.CmsgSpace(4))
	var err error
	for {
		n, oobn, _, _, rerr := c.conn.ReadMsgUnix(buf, oob)
		if rerr != nil || n == 0 {
			err = ErrParentGone
			break
		}
		fd := -1
		if oobn > 0 {
			if msgs, perr := unix.ParseSocketControlMessage(oob[:oobn]); perr == nil {
				for _, m := range msgs {
					if fds, rerr := unix.ParseUnixRights(&m); rerr == nil {
						for _, f := range fds {
							if fd < 0 {
								fd = f
							} else {
								unix.Close(f) // one descriptor per answer, never more
							}
						}
					}
				}
			}
		}
		var resp response
		if json.Unmarshal(buf[:n], &resp) != nil {
			if fd >= 0 {
				unix.Close(fd)
			}
			continue
		}
		c.mu.Lock()
		ch := c.pending[resp.ID]
		delete(c.pending, resp.ID)
		c.mu.Unlock()
		if ch == nil {
			if fd >= 0 {
				unix.Close(fd)
			}
			continue
		}
		ch <- reply{resp: resp, fd: fd}
	}
	c.mu.Lock()
	c.err = err
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	c.mu.Unlock()
	close(c.done)
}

// call sends op and waits for its answer; fd is a passed descriptor or -1.
func (c *Client) call(ctx context.Context, op string, args, result any) (fd int, err error) {
	var raw json.RawMessage
	if args != nil {
		if raw, err = json.Marshal(args); err != nil {
			return -1, err
		}
	}
	ch := make(chan reply, 1)
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return -1, c.err
	}
	c.next++
	id := c.next
	c.pending[id] = ch
	c.mu.Unlock()
	b, _ := json.Marshal(request{ID: id, Op: op, Args: raw})
	if len(b) > maxMessage {
		c.forget(id)
		return -1, fmt.Errorf("privsep: %s: request too large", op)
	}
	if _, _, err := c.conn.WriteMsgUnix(b, nil, nil); err != nil {
		c.forget(id)
		return -1, fmt.Errorf("privsep: %s: %w", op, err)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Minute)
		defer cancel()
	}
	select {
	case r, ok := <-ch:
		if !ok {
			return -1, ErrParentGone
		}
		if r.resp.Err != "" {
			if r.fd >= 0 {
				unix.Close(r.fd)
			}
			return -1, errors.New(r.resp.Err)
		}
		if result != nil && len(r.resp.Result) > 0 {
			if err := json.Unmarshal(r.resp.Result, result); err != nil {
				if r.fd >= 0 {
					unix.Close(r.fd)
				}
				return -1, fmt.Errorf("privsep: %s: %w", op, err)
			}
		}
		return r.fd, nil
	case <-ctx.Done():
		c.forget(id) // an answer that still comes is dropped (its descriptor closed)
		return -1, fmt.Errorf("privsep: %s: %w", op, ctx.Err())
	}
}

func (c *Client) forget(id uint64) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

// Hello fetches the configuration and the device key's public half.
func (c *Client) Hello(ctx context.Context) (Hello, devicekey.DeviceKey, error) {
	var h Hello
	if _, err := c.call(ctx, opHello, nil, &h); err != nil {
		return h, nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(h.PublicKey)
	if err != nil {
		return h, nil, fmt.Errorf("privsep: public key: %w", err)
	}
	if err := devicekey.CheckPublicKey(pub); err != nil {
		return h, nil, err
	}
	return h, &remoteKey{c: c, pub: pub, kind: h.KeyKind, hw: h.HardwareBound}, nil
}

// remoteKey signs through the parent; the private key never enters the
// worker.
type remoteKey struct {
	c    *Client
	pub  crypto.PublicKey
	kind string
	hw   bool
}

func (k *remoteKey) Public() crypto.PublicKey { return k.pub }
func (k *remoteKey) HardwareBound() bool      { return k.hw }
func (k *remoteKey) Kind() string             { return k.kind }

func (k *remoteKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var r signResult
	if _, err := k.c.call(context.Background(), opSign, signArgs{Digest: digest, Hash: opts.HashFunc()}, &r); err != nil {
		return nil, err
	}
	return r.Signature, nil
}

// Net is the host's network as the worker may change it, through the
// parent. Watching the machine's networks needs no privileges and stays in
// the worker; what it reads for that is opened here, before the worker
// enters its sandbox.
func (c *Client) Net() (netcfg.Configurator, error) {
	local, err := netcfg.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("privsep: %w", err)
	}
	return &remoteNet{c: c, local: local}, nil
}

type remoteNet struct {
	c     *Client
	local netcfg.Configurator
}

var (
	_ netcfg.Configurator  = (*remoteNet)(nil)
	_ netcfg.ArrivalRouter = (*remoteNet)(nil)
	_ netcfg.Watcher       = (*remoteNet)(nil)
)

func (r *remoteNet) CreateTUN(name string, mtu int) (tun.Device, string, error) {
	var res tunResult
	fd, err := r.c.call(context.Background(), opCreateTUN, tunArgs{Name: name, MTU: mtu}, &res)
	if err != nil {
		return nil, "", err
	}
	if fd < 0 {
		return nil, "", errors.New("privsep: the parent sent no device")
	}
	dev, err := netcfg.TUNFromFD(fd)
	if err != nil {
		unix.Close(fd)
		return nil, "", err
	}
	return dev, res.Name, nil
}

func (r *remoteNet) SetAddress(ctx context.Context, ifname string, addr netip.Prefix, mtu int) error {
	_, err := r.c.call(ctx, opSetAddress, addressArgs{Ifname: ifname, Addr: addr, MTU: mtu}, nil)
	return err
}

func (r *remoteNet) AddRoute(ctx context.Context, dst netip.Prefix, ifname string) error {
	_, err := r.c.call(ctx, opAddRoute, routeArgs{Dst: dst, Ifname: ifname}, nil)
	return err
}

func (r *remoteNet) DelRoute(ctx context.Context, dst netip.Prefix, ifname string) error {
	_, err := r.c.call(ctx, opDelRoute, routeArgs{Dst: dst, Ifname: ifname}, nil)
	return err
}

func (r *remoteNet) AddBypass(ctx context.Context, host netip.Addr) error {
	_, err := r.c.call(ctx, opAddBypass, hostArgs{Host: host}, nil)
	return err
}

func (r *remoteNet) DelBypass(ctx context.Context, host netip.Addr) error {
	_, err := r.c.call(ctx, opDelBypass, hostArgs{Host: host}, nil)
	return err
}

func (r *remoteNet) EnableForwarding(ctx context.Context) error {
	_, err := r.c.call(ctx, opEnableForwarding, nil, nil)
	return err
}

func (r *remoteNet) AllowForward(ctx context.Context, ifname string, on bool) (bool, error) {
	var res foundResult
	_, err := r.c.call(ctx, opAllowForward, switchArgs{Ifname: ifname, On: on}, &res)
	return res.Found, err
}

func (r *remoteNet) SetNAT(ctx context.Context, pool netip.Prefix, dsts []netip.Prefix, ifname string) error {
	_, err := r.c.call(ctx, opSetNAT, natArgs{Pool: pool, Dsts: dsts, Ifname: ifname}, nil)
	return err
}

func (r *remoteNet) ReplyViaArrival(ctx context.Context, ifname string, on bool) error {
	_, err := r.c.call(ctx, opReplyViaArrival, switchArgs{Ifname: ifname, On: on}, nil)
	return err
}

func (r *remoteNet) Watch(ctx context.Context, changed func()) bool {
	if w, ok := r.local.(netcfg.Watcher); ok {
		return w.Watch(ctx, changed)
	}
	return false
}

// Anchors is what the node trusts across restarts, as the worker has it:
// read from the parent's files in dir, which must be the parent's own
// (owner), and changed by asking the parent, which decides by its rules.
func (c *Client) Anchors(dir string, owner int, o anchors.Options) (anchors.Anchors, error) {
	o.Dir, o.Owner, o.ReadOnly, o.Shared = dir, owner, true, false
	read, err := anchors.Open(o)
	if err != nil {
		return nil, fmt.Errorf("privsep: %w", err)
	}
	return &remoteAnchors{c: c, read: read}, nil
}

type remoteAnchors struct {
	c    *Client
	read *anchors.Files
}

var _ anchors.Anchors = (*remoteAnchors)(nil)

func (r *remoteAnchors) Pin() (devicekey.SPKIHash, bool, error) { return r.read.Pin() }
func (r *remoteAnchors) Trust() (binding.Trust, error)          { return r.read.Trust() }
func (r *remoteAnchors) History() (anchors.Book, error)         { return r.read.History() }

func (r *remoteAnchors) SetPin(h devicekey.SPKIHash) error {
	_, err := r.c.call(context.Background(), opPinControl, pinArgs{SPKI: h.String()}, nil)
	return err
}

func (r *remoteAnchors) Follow(chain []binding.SignedSet) (binding.Trust, error) {
	cur, err := r.read.Trust()
	if err != nil {
		return cur, err
	}
	// nothing the parent would have to look at: the chain ends where the
	// list is (every snapshot brings the chain)
	if same, err := binding.VerifyChain(cur, chain, ""); err == nil && cur.Pinned() && same.Hash == cur.Hash && same.Genesis == cur.Genesis {
		return cur, nil
	}
	for len(chain) > 0 {
		n, size := 0, 0
		for n < len(chain) {
			size += len(chain[n].Set) + len(chain[n].Signature) + 64
			if n > 0 && size > pieceBytes {
				break
			}
			n++
		}
		var res followResult
		if _, err := r.c.call(context.Background(), opFollowSigners, followArgs{Links: chain[:n], More: n < len(chain)}, &res); err != nil {
			return cur, err
		}
		if chain = chain[n:]; len(chain) == 0 {
			return res.Trust, nil
		}
	}
	return cur, nil
}

func (r *remoteAnchors) Record(ev []anchors.Evidence) error {
	_, err := r.c.call(context.Background(), opRecord, recordArgs{Evidence: ev}, nil)
	return err
}
