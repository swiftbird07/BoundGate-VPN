package flow

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
)

// fuzzRecords packs packets for FuzzTableHandle: per packet a control byte
// and a two-byte length.
func fuzzRecords(recs ...any) []byte {
	var out []byte
	for i := 0; i < len(recs); i += 2 {
		pkt := recs[i+1].([]byte)
		out = append(out, recs[i].(byte))
		out = binary.BigEndian.AppendUint16(out, uint16(len(pkt)))
		out = append(out, pkt...)
	}
	return out
}

func helloRecord(tb testing.TB, name string) []byte {
	tb.Helper()
	c, s := net.Pipe()
	defer s.Close()
	go func() {
		_ = tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
		c.Close()
	}()
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(s, hdr); err != nil {
		tb.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := io.ReadFull(s, body); err != nil {
		tb.Fatal(err)
	}
	return append(hdr, body...)
}

// run feeds the packets of data through a table the way the node does
// (admit: Handle, then ClampMSS on Pass, TCPReset on Reset). scribble
// overwrites every packet once the table is done with it, as the reused
// read buffers of the tunnels do.
func run(t *testing.T, data []byte, scribble bool) ([]Entry, []string) {
	tb := New(Timeouts{}, nil)
	var learned []string
	tb.SetLearner(func(e *Entry, name string, addrs []netip.Addr, ttl time.Duration) {
		learned = append(learned, name)
	})
	now := time.Now()
	for len(data) >= 3 {
		ctl := data[0]
		n := int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if n > len(data) {
			n = len(data)
		}
		pkt := append([]byte(nil), data[:n]...)
		data = data[n:]
		switch {
		case ctl&0xf0 == 0x10:
			tb.Expire(now.Add(time.Duration(ctl&0x0f) * time.Minute))
			continue
		case ctl&0xf0 == 0x20:
			tb.Reevaluate(func(e *Entry) Result { return Result{Allow: ctl&1 != 0} })
			continue
		}
		h, ok := netparse.Parse(pkt)
		if !ok {
			continue
		}
		origin := Origin{Principal: "peer"}
		if ctl&0x01 != 0 {
			origin = Origin{Local: true}
		}
		decide := func(e *Entry) Result {
			return Result{Allow: ctl&0x02 != 0 || e.SNI == "allowed.example" || e.DNSName == "allowed.example", PermitBySNI: ctl&0x04 != 0}
		}
		out, e := tb.Handle(h, pkt, origin, decide)
		switch out {
		case Pass:
			netparse.ClampMSS(h, pkt, 1240)
		case Reset:
			if e == nil {
				t.Fatal("reset without a flow")
			}
			netparse.TCPReset(pkt)
		case Drop:
		default:
			t.Fatalf("outcome %d", out)
		}
		if tb.Len() > MaxEntries {
			t.Fatal("table beyond its bound")
		}
		if scribble {
			for i := range pkt {
				pkt[i] = 0xa5
			}
		}
	}
	snap := tb.Snapshot()
	for i := range snap {
		snap[i].ID, snap[i].Opened, snap[i].LastSeen = "", time.Time{}, time.Time{}
	}
	return snap, learned
}

// The flow table sees every packet from peers first. It must not panic, and
// what it keeps must not depend on the packet buffers after Handle returned
// (they are reused for the next packet).
func FuzzTableHandle(f *testing.F) {
	hello := helloRecord(f, "allowed.example")
	syn := tcp("100.96.0.2", "10.0.0.1", 40000, 443, netparse.TCPSyn, nil)
	f.Add(fuzzRecords(
		byte(0x04), syn,
		byte(0x00), tcp("10.0.0.1", "100.96.0.2", 443, 40000, netparse.TCPSyn|netparse.TCPAck, nil),
		byte(0x00), tcp("100.96.0.2", "10.0.0.1", 40000, 443, netparse.TCPAck, hello[:100]),
		byte(0x00), tcp("100.96.0.2", "10.0.0.1", 40000, 443, netparse.TCPAck, hello[100:]),
		byte(0x21), []byte{},
		byte(0x00), tcp("100.96.0.2", "10.0.0.1", 40000, 443, netparse.TCPFin|netparse.TCPAck, nil),
		byte(0x1f), []byte{},
	))
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'a', 'l', 'l', 'o', 'w', 'e', 'd', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1}
	ans := append(append([]byte{}, q...), 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 9)
	ans[2], ans[7] = 0x81, 1
	f.Add(fuzzRecords(
		byte(0x02), udp("100.96.0.2", "10.0.0.53", 5353, 53, q),
		byte(0x00), udp("10.0.0.53", "100.96.0.2", 53, 5353, ans),
		byte(0x03), udp("100.96.0.2", "10.0.0.53", 5353, 53, q),
	))
	frag := tcp("100.96.0.2", "10.0.0.1", 40001, 80, netparse.TCPSyn, make([]byte, 32))
	binary.BigEndian.PutUint16(frag[6:8], 0x2000) // MF
	later := udp("100.96.0.2", "10.0.0.1", 0, 0, make([]byte, 16))
	later[9] = netparse.ProtoTCP
	binary.BigEndian.PutUint16(later[6:8], 0x0004) // offset 32
	f.Add(fuzzRecords(byte(0x02), frag, byte(0x00), later))
	icmp := append([]byte{3, 3, 0, 0, 0, 0, 0, 0}, syn...)
	icmpPkt := make([]byte, 20+len(icmp))
	copy(icmpPkt, syn[:20])
	icmpPkt[9] = netparse.ProtoICMP
	copy(icmpPkt[12:16], ip4("10.0.0.1"))
	copy(icmpPkt[16:20], ip4("100.96.0.2"))
	copy(icmpPkt[20:], icmp)
	f.Add(fuzzRecords(byte(0x02), syn, byte(0x00), icmpPkt))
	f.Fuzz(func(t *testing.T, data []byte) {
		plain, learnedPlain := run(t, data, false)
		scribbled, learnedScribbled := run(t, data, true)
		if len(plain) != len(scribbled) || len(learnedPlain) != len(learnedScribbled) {
			t.Fatalf("%d/%d flows, %d/%d names", len(plain), len(scribbled), len(learnedPlain), len(learnedScribbled))
		}
		byKey := map[Key]Entry{}
		for _, e := range plain {
			byKey[e.Key] = e
		}
		for _, e := range scribbled {
			p, ok := byKey[e.Key]
			if !ok || p.SNI != e.SNI || p.DNSName != e.DNSName || p.Allowed != e.Allowed || p.BytesIn != e.BytesIn || p.BytesOut != e.BytesOut || p.probing != e.probing {
				t.Fatalf("the table depends on reused buffers:\n%+v\n%+v", p, e)
			}
		}
		for i := range learnedPlain {
			if learnedPlain[i] != learnedScribbled[i] {
				t.Fatal("learned names depend on reused buffers")
			}
		}
	})
}
