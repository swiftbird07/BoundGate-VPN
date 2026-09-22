//go:build linux

package netcfg

import (
	"context"
	"os"

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
	r4, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}
	r6, _ := os.ReadFile("/proc/net/ipv6_route") // no IPv6: no IPv6 defaults
	return linuxDefaults(string(r4), string(r6), c.own.has), nil
}
