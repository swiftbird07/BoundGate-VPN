package netcfg

import (
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// tunFromFD wraps the utun descriptor of a network extension (macOS, iOS).
// MTU 0: the platform set it with the network settings.
//
// The descriptor stays the extension's: NetworkExtension closes it when the
// tunnel ends. The device gets a duplicate, as WireGuard's Apple glue does,
// so that closing the device (a session that ended inside the core) does
// not close the extension's descriptor under it -- its number could be
// given to the next file the extension opens (a log, a socket), and
// NetworkExtension would later close that one instead.
func tunFromFD(fd int) (tun.Device, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(dup)
	dev, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dup), "utun"), 0)
	if err != nil {
		_ = unix.Close(dup)
		return nil, err
	}
	return dev, nil
}
