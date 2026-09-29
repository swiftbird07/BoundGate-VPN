//go:build linux

package netcfg

import (
	"context"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Watch listens to the kernel's routing messages (netlink: links, IPv4 and
// IPv6 routes) and compares the default routes in /proc when they come
// (watch.go). Listening needs no privileges.
func (c linuxCfg) Watch(ctx context.Context, changed func()) bool {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return false
	}
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return false
	}
	f := os.NewFile(uintptr(fd), "netlink")
	events := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 1<<16)
		for {
			if _, err := f.Read(buf); err != nil {
				if ctx.Err() != nil {
					return
				}
				// ENOBUFS: messages were lost, which is a change too
			}
			notify(events)
		}
	}()
	go func() {
		<-ctx.Done()
		f.Close()
	}()
	go watchDefaults(ctx, events, c.defaults, changed)
	return true
}

func (c linuxCfg) defaults() (string, error) {
	if c.tables != nil {
		r4, r6, err := c.tables.read()
		if err != nil {
			return "", err
		}
		return linuxDefaults(r4, r6, c.own.has), nil
	}
	r4, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}
	r6, _ := os.ReadFile("/proc/net/ipv6_route") // no IPv6: no IPv6 defaults
	return linuxDefaults(string(r4), string(r6), c.own.has), nil
}

// routeTables are the kernel's routing tables in /proc, opened once and
// read again from their start whenever something changed.
type routeTables struct {
	mu     sync.Mutex
	v4, v6 *os.File // v6 is nil on a machine without IPv6
}

func (t *routeTables) read() (r4, r6 string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	again := func(f *os.File) (string, error) {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
		b, err := io.ReadAll(f)
		return string(b), err
	}
	if r4, err = again(t.v4); err != nil {
		return "", "", err
	}
	if t.v6 != nil {
		r6, _ = again(t.v6)
	}
	return r4, r6, nil
}

// NewWatcher returns a configurator for a process that only watches the
// machine's networks: the worker of privilege separation, which changes
// them through its parent (internal/privsep). It opens the routing tables
// now, so that the sandbox the worker enters afterwards (internal/sandbox)
// need not leave it /proc.
func NewWatcher() (Configurator, error) {
	v4, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	v6, _ := os.Open("/proc/net/ipv6_route")
	return linuxCfg{own: &ownIfaces{}, arrival: &atomic.Bool{}, tables: &routeTables{v4: v4, v6: v6}}, nil
}
