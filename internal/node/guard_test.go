package node

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"strings"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/flow"
)

func udp4(src, dst [4]byte, sport, dport uint16) []byte {
	p := make([]byte, 28)
	p[0], p[8], p[9] = 0x45, 64, netparse.ProtoUDP
	binary.BigEndian.PutUint16(p[2:4], 28)
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	binary.BigEndian.PutUint16(p[24:26], 8)
	return p
}

// A panic while a packet is decided costs that packet: the flow table is
// usable afterwards (nothing left locked), the count goes up, and the log
// has the first panic, not one line per packet.
func TestPanicDropsOnlyThePacket(t *testing.T) {
	var logs bytes.Buffer
	g := &packetGuard{log: slog.New(slog.NewTextHandler(&logs, nil))}
	tb := flow.New(flow.Timeouts{}, nil)
	boom := func(*flow.Entry) flow.Result { panic("decider bug") }
	allow := func(*flow.Entry) flow.Result { return flow.Result{Allow: true} }
	handle := func(sport uint16, decide flow.Decider) (out flow.Outcome) {
		defer g.catch("test")
		out = flow.Drop
		p := udp4([4]byte{10, 21, 0, 2}, [4]byte{10, 60, 0, 10}, sport, 53)
		h, ok := netparse.Parse(p)
		if !ok {
			t.Fatal("test packet does not parse")
		}
		out, _ = tb.Handle(h, p, flow.Origin{Principal: "peer"}, decide)
		return out
	}
	for i := uint16(1); i <= 3; i++ {
		if out := handle(i, boom); out != flow.Drop {
			t.Fatalf("a panicking decision passed: %v", out)
		}
	}
	if out := handle(9, allow); out != flow.Pass {
		t.Fatalf("the table does not work after a panic: %v", out)
	}
	if g.panics.Load() != 3 {
		t.Fatalf("panics counted: %d", g.panics.Load())
	}
	if n := strings.Count(logs.String(), "panicked"); n != 1 {
		t.Fatalf("%d log lines for 3 panics within 10 s:\n%s", n, logs.String())
	}
}
