//go:build !linux && !darwin

package netcfg

import "golang.zx2c4.com/wireguard/tun"

func tunFromFD(int) (tun.Device, error) { return nil, ErrUnsupported }
