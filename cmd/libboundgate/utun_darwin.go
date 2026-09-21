package main

import (
	"strings"

	"golang.org/x/sys/unix"
)

// utunFD finds the utun a network extension was given: NetworkExtension
// does not hand out the descriptor, but it is open in the process, and only
// a utun control socket answers UTUN_OPT_IFNAME (what WireGuard's app does).
func utunFD() int {
	for fd := 0; fd < 1024; fd++ {
		name, err := unix.GetsockoptString(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */)
		if err == nil && strings.HasPrefix(name, "utun") {
			return fd
		}
	}
	return -1
}
