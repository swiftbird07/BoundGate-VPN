//go:build linux

package privsep

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

type testKey struct{ priv *ecdsa.PrivateKey }

func (k testKey) Public() crypto.PublicKey { return &k.priv.PublicKey }
func (k testKey) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	return k.priv.Sign(r, d, o)
}
func (testKey) HardwareBound() bool { return true }
func (testKey) Kind() string        { return "tpm2" }

// fakeNet records what the parent let through.
type fakeNet struct {
	mu    sync.Mutex
	calls []string
	file  *os.File
}

func (f *fakeNet) rec(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

type fakeDev struct {
	tun.Device
	f *os.File
}

func (d fakeDev) File() *os.File { return d.f }
func (d fakeDev) Close() error   { return d.f.Close() }

func (f *fakeNet) CreateTUN(name string, mtu int) (tun.Device, string, error) {
	f.rec("create " + name)
	r, w, _ := os.Pipe()
	w.Close()
	f.file = r
	return fakeDev{f: r}, name, nil
}
func (f *fakeNet) SetAddress(_ context.Context, ifname string, a netip.Prefix, _ int) error {
	f.rec("addr " + ifname + " " + a.String())
	return nil
}
func (f *fakeNet) AddRoute(_ context.Context, d netip.Prefix, ifname string) error {
	f.rec("route " + d.String() + " " + ifname)
	return nil
}
func (f *fakeNet) DelRoute(context.Context, netip.Prefix, string) error { return nil }
func (f *fakeNet) AddBypass(_ context.Context, h netip.Addr) error {
	f.rec("bypass " + h.String())
	return nil
}
func (f *fakeNet) DelBypass(context.Context, netip.Addr) error { return nil }
func (f *fakeNet) EnableForwarding(context.Context) error      { return nil }
func (f *fakeNet) AllowForward(context.Context, string, bool) (bool, error) {
	return true, nil
}
func (f *fakeNet) SetNAT(_ context.Context, pool netip.Prefix, dsts []netip.Prefix, ifname string) error {
	f.rec("nat " + pool.String())
	return nil
}

func pair(t *testing.T, p *Parent) *Client {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.FileConn(os.NewFile(uintptr(fds[0]), "parent"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { _ = p.Serve(ctx, pc.(*net.UnixConn)); close(served) }()
	c, err := Dial(os.NewFile(uintptr(fds[1]), "worker"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); pc.Close(); c.conn.Close(); <-served })
	return c
}

// The worker signs through the parent, gets the device as a descriptor,
// and changes only what concerns that device.
func TestTheParentAnswersOnlyWhatItsRulesAllow(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fn := &fakeNet{}
	p := &Parent{Key: testKey{priv}, Net: fn, Config: []byte("name: n1\n"), TUNName: "bg0", WorkerUID: 65531, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c := pair(t, p)
	ctx := context.Background()

	h, key, err := c.Hello(ctx)
	if err != nil || string(h.Config) != "name: n1\n" || !key.HardwareBound() || key.Kind() != "tpm2" || h.WorkerUID != 65531 {
		t.Fatalf("hello: %+v %v", h, err)
	}
	d := sha256.Sum256([]byte("handshake"))
	sig, err := key.Sign(nil, d[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(&priv.PublicKey, d[:], sig) {
		t.Fatalf("signature through the parent: %v", err)
	}
	if _, err := key.Sign(nil, d[:20], crypto.SHA256); err == nil {
		t.Fatal("a digest of the wrong length was signed")
	}
	if _, err := key.Sign(nil, d[:20], crypto.SHA1); err == nil {
		t.Fatal("a SHA-1 digest was signed")
	}

	net := &remoteNet{c: c}
	// nothing about a device before the node's own exists
	if err := net.AddRoute(ctx, netip.MustParsePrefix("10.0.0.0/8"), "eth0"); err == nil {
		t.Fatal("a route on another interface was added")
	}
	if _, err := c.call(ctx, opCreateTUN, tunArgs{Name: "eth0", MTU: 1400}, nil); err == nil {
		t.Fatal("a device of another name was created")
	}
	fd, err := c.call(ctx, opCreateTUN, tunArgs{Name: "bg0", MTU: 1400}, &tunResult{})
	if err != nil || fd < 0 {
		t.Fatalf("create: fd %d %v", fd, err)
	}
	unix.Close(fd)
	for _, bad := range []error{
		net.AddRoute(ctx, netip.MustParsePrefix("10.0.0.0/8"), "eth0"),
		net.AddRoute(ctx, netip.MustParsePrefix("10.1.2.3/8"), "bg0"),
		net.SetAddress(ctx, "eth0", netip.MustParsePrefix("10.21.0.4/16"), 1400),
		net.AddBypass(ctx, netip.MustParseAddr("127.0.0.1")),
		net.AddBypass(ctx, netip.MustParseAddr("224.0.0.1")),
		net.SetNAT(ctx, netip.MustParsePrefix("8.8.8.0/24"), []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, "bg0"),
		net.SetNAT(ctx, netip.MustParsePrefix("10.21.0.0/16"), nil, "eth0"),
		net.SetNAT(ctx, netip.MustParsePrefix("100.0.0.0/6"), []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, "bg0"),
		net.ReplyViaArrival(ctx, "bg0", true), // the fake host cannot
	} {
		if bad == nil {
			t.Fatal("a request against the rules went through")
		}
	}
	for _, err := range []error{
		net.SetAddress(ctx, "bg0", netip.MustParsePrefix("10.21.0.4/16"), 1400),
		net.AddRoute(ctx, netip.MustParsePrefix("10.60.0.0/24"), "bg0"),
		net.AddBypass(ctx, netip.MustParseAddr("203.0.113.7")),
		net.SetNAT(ctx, netip.MustParsePrefix("10.21.0.0/16"), []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, "bg0"),
		net.SetNAT(ctx, netip.MustParsePrefix("100.96.0.0/16"), []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, "bg0"), // shared address space, as the rehearsal's pool
	} {
		if err != nil {
			t.Fatalf("an allowed request failed: %v", err)
		}
	}
	fn.mu.Lock()
	got := strings.Join(fn.calls, "; ")
	fn.mu.Unlock()
	if got != "create bg0; addr bg0 10.21.0.4/16; route 10.60.0.0/24 bg0; bypass 203.0.113.7; nat 10.21.0.0/16; nat 100.96.0.0/16" {
		t.Fatalf("the host saw: %s", got)
	}
	if _, err := c.call(ctx, "exec", nil, nil); err == nil {
		t.Fatal("an unknown operation was answered")
	}
}

// When the parent goes, every call fails and Done closes: the worker ends.
func TestTheWorkerNoticesTheParentIsGone(t *testing.T) {
	fds, _ := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	c, err := Dial(os.NewFile(uintptr(fds[1]), "worker"))
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fds[0])
	<-c.Done()
	if _, _, err := c.Hello(context.Background()); !errors.Is(err, ErrParentGone) {
		t.Fatalf("after the parent: %v", err)
	}
}
