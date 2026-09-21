package netcfg

import (
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

// tunFromFD wraps the utun descriptor of a network extension (macOS, iOS).
// MTU 0: the platform set it with the network settings.
func tunFromFD(fd int) (tun.Device, error) {
	return tun.CreateTUNFromFile(os.NewFile(uintptr(fd), "utun"), 0)
}
