//go:build !linux

package netcfg

import (
	"context"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
)

type unsupported struct{}

// New returns a configurator that refuses everything. macOS support lands in
// milestone M5 (utun via the tun package, route/scutil for the rest).
func New() Configurator { return unsupported{} }

func (unsupported) CreateTUN(string, int) (tun.Device, string, error) { return nil, "", ErrUnsupported }
func (unsupported) SetAddress(context.Context, string, netip.Prefix, int) error {
	return ErrUnsupported
}
func (unsupported) AddRoute(context.Context, netip.Prefix, string) error { return ErrUnsupported }
func (unsupported) DelRoute(context.Context, netip.Prefix, string) error { return ErrUnsupported }
func (unsupported) AddBypass(context.Context, netip.Addr) error          { return ErrUnsupported }
func (unsupported) DelBypass(context.Context, netip.Addr) error          { return ErrUnsupported }
func (unsupported) EnableForwarding(context.Context) error               { return ErrUnsupported }
func (unsupported) SetNAT(context.Context, netip.Prefix, []netip.Prefix, string) error {
	return ErrUnsupported
}
