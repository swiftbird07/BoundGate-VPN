package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/forward"
)

// dataplane owns the TUN device and moves packets between the host stack,
// accepted tunnels (hub role) and the uplink to the primary hub (spoke).
//
//	host stack ─▶ TUN ─▶ table hit? ─▶ that tunnel
//	                     else uplink? ─▶ primary hub
//	                     else drop
//	tunnel ─▶ Route(): table hit (other tunnel)? ─▶ there, else ─▶ TUN
type dataplane struct {
	dev    tun.Device
	ifname string
	table  *forward.Table
	uplink atomic.Pointer[uplinkRef]
	log    *slog.Logger

	wmu   sync.Mutex
	wbufs [][]byte
}

type uplinkRef struct{ pw forward.PacketWriter }

func newDataplane(dev tun.Device, ifname string, log *slog.Logger) *dataplane {
	return &dataplane{dev: dev, ifname: ifname, table: forward.NewTable(), log: log, wbufs: make([][]byte, 1)}
}

// setUplink installs (or clears, with nil) the tunnel that carries traffic
// for destinations no accepted tunnel owns.
func (d *dataplane) setUplink(pw forward.PacketWriter) {
	if pw == nil {
		d.uplink.Store(nil)
		return
	}
	d.uplink.Store(&uplinkRef{pw: pw})
}

func (d *dataplane) getUplink() forward.PacketWriter {
	if r := d.uplink.Load(); r != nil {
		return r.pw
	}
	return nil
}

// WriteToTUN hands one packet to the host stack. buf must have Offset spare
// bytes in front: the packet is buf[Offset:].
func (d *dataplane) WriteToTUN(buf []byte) error {
	if len(buf) <= forward.Offset {
		return errors.New("dataplane: short buffer")
	}
	d.wmu.Lock()
	defer d.wmu.Unlock()
	d.wbufs[0] = buf
	_, err := d.dev.Write(d.wbufs, forward.Offset)
	return err
}

// Route delivers a packet that arrived from a tunnel: to another tunnel
// that owns the destination, otherwise to the host stack. ICMP errors from
// the next hop go back to the sender.
func (d *dataplane) Route(buf []byte, from forward.PacketWriter) {
	pkt := buf[forward.Offset:]
	h, ok := netparse.Parse(pkt)
	if ok {
		if pw, ok := d.table.Lookup(h.Dst); ok && pw != from {
			icmp, err := pw.WritePacket(pkt)
			if err == nil && icmp != nil && from != nil {
				_, _ = from.WritePacket(icmp)
			}
			return
		}
	}
	if err := d.WriteToTUN(buf); err != nil {
		d.log.Warn("tun write", "err", err)
	}
}

// RunTUNReader reads packets from the host stack until ctx ends.
func (d *dataplane) RunTUNReader(ctx context.Context) error {
	batch := d.dev.BatchSize()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, forward.Offset+forward.MaxPacket+forward.Offset)
	}
	sizes := make([]int, batch)
	go func() {
		<-ctx.Done()
		_ = d.dev.Close()
	}()
	var dropped uint64
	for {
		n, err := d.dev.Read(bufs, sizes, forward.Offset)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return nil
			}
			if errors.Is(err, tun.ErrTooManySegments) {
				continue
			}
			return fmt.Errorf("dataplane: tun read: %w", err)
		}
		for i := 0; i < n; i++ {
			pkt := bufs[i][forward.Offset : forward.Offset+sizes[i]]
			// Only IPv4 runs on the overlay. The kernel also emits IPv6
			// link-local traffic (router solicitations, MLD) on a fresh TUN.
			if len(pkt) == 0 || pkt[0]>>4 != 4 {
				continue
			}
			h, ok := netparse.Parse(pkt)
			if !ok {
				continue
			}
			pw, ok := d.table.Lookup(h.Dst)
			if !ok {
				pw = d.getUplink()
			}
			if pw == nil {
				dropped++
				if dropped == 1 || dropped%1000 == 0 {
					d.log.Debug("no path for packet from host stack", "dst", h.Dst, "dropped", dropped)
				}
				continue
			}
			icmp, err := pw.WritePacket(pkt)
			if err != nil {
				continue // tunnel is gone; its owner detaches it
			}
			if icmp != nil {
				b := make([]byte, forward.Offset+len(icmp))
				copy(b[forward.Offset:], icmp)
				_ = d.WriteToTUN(b)
			}
		}
	}
}
