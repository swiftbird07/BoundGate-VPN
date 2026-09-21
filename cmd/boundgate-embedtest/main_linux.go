// Command boundgate-embedtest runs a node through internal/embed, the way the
// iOS and Android apps do, on Linux: it plays the platform (a tun device by
// descriptor, network settings applied in one piece, the device key as a
// signer) and serves the engine's requests on the daemon's socket, so
// boundgatectl and the lab scripts drive it like any other node. Lab only
// (compose service node-m): it proves the embedded path against a real
// control plane and hubs before a phone is involved.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey/softkey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/embed"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
)

func main() {
	state := flag.String("state", "/var/lib/boundgate", "state directory")
	socket := flag.String("socket", "/run/boundgate/node.sock", "socket for boundgatectl")
	control := flag.String("control", "", "control plane host:port, configured on first start")
	serverName := flag.String("server-name", "", "node SNI of the control plane")
	name := flag.String("name", "node-m", "device name")
	ifname := flag.String("tun", "bgm0", "tun device name")
	memLimit := flag.Int("memory-limit-mib", 40, "soft heap limit, as on iOS")
	flag.Parse()

	key, err := softkey.New(filepath.Join(*state, "device.key")).Open(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	p := &linuxPlatform{key: key, ifname: *ifname, fd: -1}
	e, err := embed.Start(embed.Config{StateDir: *state, Platform: "embedtest", Name: *name, MemoryLimitMiB: *memLimit, LogLevel: "info"}, p)
	if err != nil {
		log.Fatal(err)
	}
	defer e.Stop()
	if *control != "" {
		var st struct{ State string }
		_, b := e.Request("GET", "/v1/status", nil)
		_ = json.Unmarshal(b, &st)
		if st.State == "unconfigured" {
			body, _ := json.Marshal(map[string]string{"control_addr": *control, "control_server_name": *serverName, "name": *name})
			if code, b := e.Request("POST", "/v1/configure", body); code != http.StatusOK {
				log.Fatalf("configure: %d %s", code, b)
			}
		}
	}

	_ = os.MkdirAll(filepath.Dir(*socket), 0o755)
	_ = os.Remove(*socket)
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		code, out := e.Request(r.Method, r.URL.RequestURI(), body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write(out)
	})}
	go func() { _ = srv.Serve(ln) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	_ = srv.Close()
}

// linuxPlatform is what the iOS and Android apps implement, done with a tun
// device and ip(8).
type linuxPlatform struct {
	key    devicekey.DeviceKey
	ifname string

	mu     sync.Mutex
	fd     int
	addr   string
	mtu    int
	routes map[string]bool
}

func (p *linuxPlatform) Apply(s netcfg.NetworkSettings) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fd < 0 {
		fd, err := openTUN(p.ifname)
		if err != nil {
			return -1, err
		}
		p.fd, p.addr, p.mtu, p.routes = fd, "", 0, map[string]bool{}
	}
	if a := s.Address.String(); a != p.addr {
		if p.addr != "" {
			_ = ip("addr", "del", p.addr, "dev", p.ifname)
		}
		if err := ip("addr", "replace", a, "dev", p.ifname); err != nil {
			return -1, err
		}
		p.addr = a
	}
	if s.MTU != p.mtu {
		if err := ip("link", "set", p.ifname, "mtu", fmt.Sprint(s.MTU), "up"); err != nil {
			return -1, err
		}
		p.mtu = s.MTU
	}
	want := map[string]bool{}
	for _, r := range s.Routes {
		want[r.String()] = true
		if !p.routes[r.String()] {
			if err := ip("route", "replace", r.String(), "dev", p.ifname); err != nil {
				return -1, err
			}
		}
	}
	for r := range p.routes {
		if !want[r] {
			_ = ip("route", "del", r, "dev", p.ifname)
		}
	}
	p.routes = want
	// Excluded hosts (control plane, hubs) are in the lab's own subnet and
	// never covered by a route; a phone keeps its app's sockets outside.
	log.Printf("platform: applied %s mtu %d, %d routes, %d excluded", s.Address, s.MTU, len(s.Routes), len(s.Excluded))
	return p.fd, nil
}

// Release: the core closed the descriptor, and with it the device went away.
func (p *linuxPlatform) Release() {
	p.mu.Lock()
	p.fd = -1
	p.mu.Unlock()
	log.Printf("platform: released")
}

func (p *linuxPlatform) PublicKey() ([]byte, error) { return x509.MarshalPKIXPublicKey(p.key.Public()) }
func (p *linuxPlatform) Sign(d []byte) ([]byte, error) {
	return p.key.Sign(rand.Reader, d, crypto.SHA256)
}
func (p *linuxPlatform) KeyKind() string     { return p.key.Kind() }
func (p *linuxPlatform) HardwareBound() bool { return p.key.HardwareBound() }
func (p *linuxPlatform) Log(level int, line string) {
	fmt.Fprintln(os.Stderr, strings.TrimSpace(line))
}

func ip(args ...string) error {
	var errb bytes.Buffer
	cmd := exec.Command("ip", args...)
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return nil
}

// openTUN creates a tun device without packet information and without a
// virtio header: what Android's VpnService hands out.
func openTUN(name string) (int, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var ifr [40]byte
	copy(ifr[:16], name)
	*(*uint16)(unsafe.Pointer(&ifr[16])) = syscall.IFF_TUN | syscall.IFF_NO_PI
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		syscall.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF %s: %v", name, errno)
	}
	return fd, nil
}
