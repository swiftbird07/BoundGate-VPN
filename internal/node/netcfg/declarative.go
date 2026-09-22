package netcfg

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// NetworkSettings is the whole network configuration of an embedded node,
// handed to its Platform in one piece: iOS (NEPacketTunnelNetworkSettings),
// Android (VpnService.Builder) and macOS network extensions take it that way
// and not as single commands.
type NetworkSettings struct {
	// Address is the overlay address of this node (a host prefix).
	Address netip.Prefix `json:"address"`
	MTU     int          `json:"mtu"`
	// Routes go into the tunnel, sorted. 0.0.0.0/0 arrives as its two halves.
	Routes []netip.Prefix `json:"routes"`
	// Excluded are hosts that must stay outside the tunnel even when a route
	// covers them: the control plane, hubs, the identity provider. Where the
	// platform keeps the app's own sockets out of the tunnel anyway (iOS and
	// macOS network extensions, Android with the app disallowed) they need
	// nothing, but a route for them does no harm.
	Excluded []netip.Addr `json:"excluded,omitempty"`
}

// Platform applies network settings for an embedded node.
type Platform interface {
	// Apply installs s and returns the file descriptor of the tunnel device.
	// Returning the descriptor of the previous call keeps the device (iOS
	// keeps its utun); a new one replaces it (Android establishes a new
	// interface for every change) and the core closes the old one. The core
	// owns every descriptor it was given.
	Apply(s NetworkSettings) (fd int, err error)
	// Release: the overlay is down, the core closed the device.
	Release()
}

// Declarative is a Configurator for embedded nodes: it keeps the desired
// state and hands all of it to the platform after every change, coalescing
// changes that come in a burst (bringing the overlay up, a hub advertising
// its routes, teardown). Forwarding and NAT are refused: an embedded node is
// an endpoint.
type Declarative struct {
	p     Platform
	log   *slog.Logger
	delay time.Duration
	// open makes a device from a descriptor (tunFromFD; replaced in tests)
	open func(fd int) (tun.Device, error)

	mu       sync.Mutex
	dev      *swapTUN
	settings NetworkSettings
	routes   map[netip.Prefix]bool
	excluded map[netip.Addr]bool
	timer    *time.Timer
	fd       int
	lastErr  error
}

// NewDeclarative returns a configurator that applies through p.
func NewDeclarative(p Platform, log *slog.Logger) *Declarative {
	if log == nil {
		log = slog.Default()
	}
	return &Declarative{p: p, log: log, delay: 50 * time.Millisecond, open: tunFromFD, fd: -1,
		routes: map[netip.Prefix]bool{}, excluded: map[netip.Addr]bool{}}
}

// Err is the error of the last Apply (nil when it worked).
func (d *Declarative) Err() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastErr
}

func (d *Declarative) CreateTUN(name string, mtu int) (tun.Device, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dev != nil && !d.dev.isClosed() {
		return nil, "", errors.New("netcfg: the tunnel device is already open")
	}
	d.dev = newSwapTUN(mtu, d.release)
	d.settings = NetworkSettings{MTU: mtu}
	d.routes = map[netip.Prefix]bool{}
	d.fd = -1
	d.lastErr = nil
	return d.dev, "tunnel", nil
}

func (d *Declarative) SetAddress(_ context.Context, _ string, addr netip.Prefix, mtu int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.settings.Address, d.settings.MTU = addr, mtu
	d.scheduleLocked()
	return nil
}

func (d *Declarative) AddRoute(_ context.Context, dst netip.Prefix, _ string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.routes[dst.Masked()] {
		d.routes[dst.Masked()] = true
		d.scheduleLocked()
	}
	return nil
}

func (d *Declarative) DelRoute(_ context.Context, dst netip.Prefix, _ string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.routes[dst.Masked()] {
		delete(d.routes, dst.Masked())
		d.scheduleLocked()
	}
	return nil
}

func (d *Declarative) AddBypass(_ context.Context, host netip.Addr) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.excluded[host] {
		d.excluded[host] = true
		d.scheduleLocked()
	}
	return nil
}

func (d *Declarative) DelBypass(_ context.Context, host netip.Addr) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.excluded[host] {
		delete(d.excluded, host)
		d.scheduleLocked()
	}
	return nil
}

// Refresh hands the current settings to the platform again, for a platform
// whose own part of them follows the network underneath (Android copies the
// DNS servers of the network below into the VPN). A platform that returns the
// same descriptor keeps its device; a new one replaces it as after any change.
func (d *Declarative) Refresh() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.scheduleLocked()
}

var errEndpointOnly = errors.New("netcfg: an embedded node is an endpoint: it does not forward (hub, subnet router and exit node need the daemon)")

func (d *Declarative) EnableForwarding(context.Context) error { return errEndpointOnly }
func (d *Declarative) AllowForward(_ context.Context, _ string, on bool) (bool, error) {
	if on {
		return false, errEndpointOnly
	}
	return false, nil
}
func (d *Declarative) SetNAT(_ context.Context, _ netip.Prefix, dsts []netip.Prefix, _ string) error {
	if len(dsts) > 0 {
		return errEndpointOnly
	}
	return nil
}

// scheduleLocked applies the state after a short quiet time; nothing
// happens before the address is known or after the device was closed.
func (d *Declarative) scheduleLocked() {
	if d.dev == nil || d.dev.isClosed() || !d.settings.Address.IsValid() {
		return
	}
	if d.timer != nil {
		d.timer.Stop()
	}
	dev := d.dev
	d.timer = time.AfterFunc(d.delay, func() { d.apply(dev) })
}

func (d *Declarative) apply(dev *swapTUN) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if dev != d.dev || dev.isClosed() {
		return
	}
	s := d.settings
	s.Routes = sortedKeys(d.routes, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	s.Excluded = sortedKeys(d.excluded, func(a, b netip.Addr) int { return a.Compare(b) })
	// the platform may take its time (iOS answers asynchronously); the
	// device keeps its state meanwhile and no other apply runs
	fd, err := d.p.Apply(s)
	d.lastErr = err
	if err != nil {
		d.log.Error("the platform refused the network settings", "err", err, "address", s.Address, "routes", len(s.Routes))
		return
	}
	if fd == d.fd {
		return
	}
	nd, err := d.open(fd)
	if err != nil {
		d.lastErr = err
		d.log.Error("tunnel device from the platform", "fd", fd, "err", err)
		return
	}
	d.fd = fd
	dev.swap(nd)
}

func (d *Declarative) release() {
	d.mu.Lock()
	if d.timer != nil {
		d.timer.Stop()
	}
	d.fd = -1
	d.mu.Unlock()
	d.p.Release()
}

func sortedKeys[K comparable](m map[K]bool, cmp func(a, b K) int) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.SortFunc(out, cmp)
	return out
}

// swapTUN is the device the node reads and writes. The platform's device
// behind it can be replaced while it is in use: a read on a device that is
// being replaced goes on on the new one. Until the first device arrives,
// reads wait and writes are dropped (like a network that is not up yet).
type swapTUN struct {
	mtu     int
	onClose func()

	mu     sync.Mutex
	cond   *sync.Cond
	dev    tun.Device
	gen    int
	closed bool
	events chan tun.Event
}

func newSwapTUN(mtu int, onClose func()) *swapTUN {
	t := &swapTUN{mtu: mtu, onClose: onClose, events: make(chan tun.Event)}
	t.cond = sync.NewCond(&t.mu)
	return t
}

func (t *swapTUN) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func (t *swapTUN) swap(nd tun.Device) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = nd.Close()
		return
	}
	old := t.dev
	t.dev = nd
	t.gen++
	t.cond.Broadcast()
	t.mu.Unlock()
	if old != nil {
		_ = old.Close() // a read blocked on it returns and goes on on nd
	}
}

func (t *swapTUN) current() (tun.Device, int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for t.dev == nil && !t.closed {
		t.cond.Wait()
	}
	if t.closed {
		return nil, 0, os.ErrClosed
	}
	return t.dev, t.gen, nil
}

func (t *swapTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		dev, gen, err := t.current()
		if err != nil {
			return 0, err
		}
		n, err := dev.Read(bufs[:1], sizes[:1], offset)
		if err == nil {
			return n, nil
		}
		t.mu.Lock()
		closed, swapped := t.closed, t.gen != gen
		t.mu.Unlock()
		if closed {
			return 0, os.ErrClosed
		}
		if !swapped {
			return 0, err
		}
	}
}

func (t *swapTUN) Write(bufs [][]byte, offset int) (int, error) {
	t.mu.Lock()
	dev := t.dev
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return 0, os.ErrClosed
	}
	if dev == nil {
		return len(bufs), nil
	}
	n, err := dev.Write(bufs, offset)
	if err != nil && t.isClosed() {
		return 0, os.ErrClosed
	}
	return n, err
}

func (t *swapTUN) File() *os.File {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dev == nil {
		return nil
	}
	return t.dev.File()
}

func (t *swapTUN) MTU() (int, error) { return t.mtu, nil }

func (t *swapTUN) Name() (string, error) {
	t.mu.Lock()
	dev := t.dev
	t.mu.Unlock()
	if dev == nil {
		return "tunnel", nil
	}
	return dev.Name()
}

func (t *swapTUN) Events() <-chan tun.Event { return t.events }

// BatchSize is 1: devices from a descriptor (utun, Android's tun) move one
// packet per call, and the value must not change when the device does.
func (t *swapTUN) BatchSize() int { return 1 }

func (t *swapTUN) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	dev := t.dev
	t.dev = nil
	t.cond.Broadcast()
	close(t.events)
	t.mu.Unlock()
	var err error
	if dev != nil {
		err = dev.Close()
	}
	if t.onClose != nil {
		t.onClose()
	}
	return err
}
