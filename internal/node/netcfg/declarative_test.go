package netcfg

import (
	"context"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// chanTUN is a device made of channels: in is what the host stack "sends".
type chanTUN struct {
	fd     int
	in     chan []byte
	out    chan []byte
	once   sync.Once
	closed chan struct{}
}

func newChanTUN(fd int) *chanTUN {
	return &chanTUN{fd: fd, in: make(chan []byte, 4), out: make(chan []byte, 4), closed: make(chan struct{})}
}

func (c *chanTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-c.in:
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	case <-c.closed:
		return 0, os.ErrClosed
	}
}
func (c *chanTUN) Write(bufs [][]byte, offset int) (int, error) {
	c.out <- append([]byte(nil), bufs[0][offset:]...)
	return 1, nil
}
func (c *chanTUN) File() *os.File           { return nil }
func (c *chanTUN) MTU() (int, error)        { return 1230, nil }
func (c *chanTUN) Name() (string, error)    { return "utun9", nil }
func (c *chanTUN) Events() <-chan tun.Event { return nil }
func (c *chanTUN) BatchSize() int           { return 1 }
func (c *chanTUN) Close() error             { c.once.Do(func() { close(c.closed) }); return nil }

// fakePlatform hands out a new descriptor per Apply, like Android.
type fakePlatform struct {
	mu       sync.Mutex
	applied  []NetworkSettings
	newFD    bool
	released int
}

func (p *fakePlatform) Apply(s NetworkSettings) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.applied = append(p.applied, s)
	if p.newFD {
		return 100 + len(p.applied), nil
	}
	return 7, nil
}
func (p *fakePlatform) Release() { p.mu.Lock(); p.released++; p.mu.Unlock() }
func (p *fakePlatform) calls() []NetworkSettings {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]NetworkSettings(nil), p.applied...)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestDeclarativeCoalescesAndSwapsDevices(t *testing.T) {
	ctx := context.Background()
	p := &fakePlatform{newFD: true}
	d := NewDeclarative(p, nil)
	devs := map[int]*chanTUN{}
	var mu sync.Mutex
	d.open = func(fd int) (tun.Device, error) {
		mu.Lock()
		defer mu.Unlock()
		devs[fd] = newChanTUN(fd)
		return devs[fd], nil
	}
	dev, _, err := d.CreateTUN("bg0", 1230)
	if err != nil {
		t.Fatal(err)
	}
	// before the first device: writes are dropped, reads wait
	if n, err := dev.Write([][]byte{[]byte("xx")}, 0); n != 1 || err != nil {
		t.Fatalf("write before the device: %d %v", n, err)
	}
	got := make(chan string, 4)
	go func() {
		buf := [][]byte{make([]byte, 100)}
		sizes := []int{0}
		for {
			if _, err := dev.Read(buf, sizes, 0); err != nil {
				close(got)
				return
			}
			got <- string(buf[0][:sizes[0]])
		}
	}()

	// the burst of bringing the overlay up is one Apply
	_ = d.AddBypass(ctx, netip.MustParseAddr("136.243.123.200"))
	_ = d.SetAddress(ctx, "", netip.MustParsePrefix("10.25.0.1/32"), 1230)
	_ = d.AddRoute(ctx, netip.MustParsePrefix("10.25.0.0/16"), "")
	_ = d.AddRoute(ctx, netip.MustParsePrefix("10.20.0.0/16"), "")
	_ = d.AddRoute(ctx, netip.MustParsePrefix("10.20.0.0/16"), "") // idempotent
	waitFor(t, "first apply", func() bool { return len(p.calls()) == 1 })
	s := p.calls()[0]
	if s.Address != netip.MustParsePrefix("10.25.0.1/32") || s.MTU != 1230 || len(s.Routes) != 2 ||
		s.Routes[0] != netip.MustParsePrefix("10.20.0.0/16") || len(s.Excluded) != 1 {
		t.Fatalf("settings %+v", s)
	}
	mu.Lock()
	first := devs[101]
	mu.Unlock()
	first.in <- []byte("one")
	if v := <-got; v != "one" {
		t.Fatal(v)
	}

	// a change brings a new descriptor: the reader goes on on the new device
	_ = d.AddRoute(ctx, netip.MustParsePrefix("0.0.0.0/1"), "")
	waitFor(t, "second apply", func() bool { return len(p.calls()) == 2 })
	mu.Lock()
	second := devs[102]
	mu.Unlock()
	select {
	case <-first.closed:
	case <-time.After(time.Second):
		t.Fatal("the replaced device was not closed")
	}
	second.in <- []byte("two")
	if v := <-got; v != "two" {
		t.Fatal(v)
	}
	if _, err := dev.Write([][]byte{[]byte("back")}, 0); err != nil {
		t.Fatal(err)
	}
	if v := <-second.out; string(v) != "back" {
		t.Fatal(string(v))
	}

	// teardown: closing the device releases the platform; the route
	// removals that follow it apply nothing
	_ = dev.Close()
	if _, ok := <-got; ok {
		t.Fatal("read after close")
	}
	_ = d.DelRoute(ctx, netip.MustParsePrefix("10.20.0.0/16"), "")
	time.Sleep(3 * d.delay)
	if len(p.calls()) != 2 || p.released != 1 {
		t.Fatalf("after close: %d applies, %d releases", len(p.calls()), p.released)
	}
	// and the next overlay starts from scratch
	if _, _, err := d.CreateTUN("bg0", 1230); err != nil {
		t.Fatal(err)
	}
}

func TestDeclarativeKeepsTheDeviceWhenTheDescriptorStays(t *testing.T) {
	ctx := context.Background()
	p := &fakePlatform{} // always fd 7, like iOS
	d := NewDeclarative(p, nil)
	opened := 0
	d.open = func(fd int) (tun.Device, error) { opened++; return newChanTUN(fd), nil }
	if _, _, err := d.CreateTUN("bg0", 1230); err != nil {
		t.Fatal(err)
	}
	_ = d.SetAddress(ctx, "", netip.MustParsePrefix("10.25.0.1/32"), 1230)
	waitFor(t, "apply", func() bool { return len(p.calls()) == 1 })
	_ = d.AddRoute(ctx, netip.MustParsePrefix("10.20.0.0/16"), "")
	waitFor(t, "apply", func() bool { return len(p.calls()) == 2 })
	// a network change hands the same settings over again (Android copies
	// the DNS of the network below); the same descriptor keeps the device
	d.Refresh()
	waitFor(t, "refresh", func() bool { return len(p.calls()) == 3 })
	if c := p.calls(); len(c[2].Routes) != 1 || c[2].Address != c[1].Address {
		t.Fatalf("refresh applied %+v", c[2])
	}
	if opened != 1 {
		t.Fatalf("opened %d devices for one descriptor", opened)
	}
	if err := d.EnableForwarding(ctx); err == nil {
		t.Fatal("an embedded node must not forward")
	}
	if err := d.SetNAT(ctx, netip.Prefix{}, nil, ""); err != nil {
		t.Fatal("removing NAT is a no-op")
	}
}
