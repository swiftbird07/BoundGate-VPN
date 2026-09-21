package netcfg

import "golang.zx2c4.com/wireguard/tun"

// tunFromFD wraps a tun descriptor (Android's VpnService, or a test on Linux).
func tunFromFD(fd int) (tun.Device, error) {
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return dev, err
}
