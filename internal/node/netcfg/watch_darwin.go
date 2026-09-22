//go:build darwin

package netcfg

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// Watch reads the routing socket (every change of routes, addresses and
// interfaces) and compares the default routes from netstat(1) when one
// comes (watch.go). Reading the routing socket needs no privileges.
func (c darwinCfg) Watch(ctx context.Context, changed func()) bool {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return false
	}
	f := os.NewFile(uintptr(fd), "route")
	events := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := f.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if darwinRelevant(buf[:n]) {
				notify(events)
			}
		}
	}()
	go func() {
		<-ctx.Done()
		f.Close()
	}()
	go watchDefaults(ctx, events, c.defaults, changed)
	return true
}

// darwinRelevant filters the routing socket's chatter: link-layer entries
// (ARP and neighbor cache, cloned per host on the LAN) come and go all the
// time and never move a default route.
func darwinRelevant(msg []byte) bool {
	if len(msg) < 12 {
		return false
	}
	switch msg[3] { // rtm_type
	case unix.RTM_IFINFO, unix.RTM_NEWADDR, unix.RTM_DELADDR:
		return true
	case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE:
		flags := int32(binary.NativeEndian.Uint32(msg[8:12])) // rtm_flags
		return flags&unix.RTF_GATEWAY != 0
	}
	return false
}

func (c darwinCfg) defaults() (string, error) {
	out, err := exec.Command("/usr/sbin/netstat", "-rn").Output()
	if err != nil {
		return "", err
	}
	return darwinDefaults(string(out), darwinTunnel), nil
}

// darwinTunnel: a default route over any utun is never a path for the host
// routes (AddBypass refuses to pin there), and macOS keeps several of them
// that come and go by themselves (link-local IPv6 defaults of its own utuns,
// other VPNs).
func darwinTunnel(ifname string) bool { return strings.HasPrefix(ifname, "utun") }
