package flow

import (
	"encoding/binary"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
)

func tcp(src, dst string, sport, dport uint16, flags uint8, payload []byte) []byte {
	pkt := make([]byte, 40+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8], pkt[9] = 64, netparse.ProtoTCP
	copy(pkt[12:16], ip4(src))
	copy(pkt[16:20], ip4(dst))
	t := pkt[20:]
	binary.BigEndian.PutUint16(t[0:2], sport)
	binary.BigEndian.PutUint16(t[2:4], dport)
	t[12] = 5 << 4
	t[13] = flags
	copy(pkt[40:], payload)
	return pkt
}

func udp(src, dst string, sport, dport uint16, payload []byte) []byte {
	pkt := make([]byte, 28+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8], pkt[9] = 64, netparse.ProtoUDP
	copy(pkt[12:16], ip4(src))
	copy(pkt[16:20], ip4(dst))
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	return pkt
}

func ip4(s string) []byte {
	var b [4]byte
	var i, v int
	for _, c := range s {
		if c == '.' {
			b[i] = byte(v)
			i, v = i+1, 0
			continue
		}
		v = v*10 + int(c-'0')
	}
	b[3] = byte(v)
	return b[:]
}

func parse(t *testing.T, pkt []byte) netparse.Header {
	h, ok := netparse.Parse(pkt)
	if !ok {
		t.Fatal("bad test packet")
	}
	return h
}

func TestFlowLifecycle(t *testing.T) {
	var events []Event
	tb := New(Timeouts{TCP: time.Hour, Closing: time.Millisecond, Deny: time.Millisecond}, func(e Event) { events = append(events, e) })
	peer := Origin{Principal: "node-a"}
	calls := 0
	allow80 := func(e *Entry) Result {
		calls++
		return Result{Allow: e.Target.Port() == 80, Policies: []string{"web"}}
	}
	syn := tcp("10.21.0.2", "10.60.0.10", 40000, 80, netparse.TCPSyn, nil)
	if out, e := tb.Handle(parse(t, syn), syn, peer, allow80); out != Pass || !e.Allowed || e.Result.Policies[0] != "web" {
		t.Fatalf("syn: %v %+v", out, e)
	}
	synack := tcp("10.60.0.10", "10.21.0.2", 80, 40000, netparse.TCPSyn|netparse.TCPAck, nil)
	if out, e := tb.Handle(parse(t, synack), synack, Origin{Local: true}, nil); out != Pass || e.PacketsOut != 1 {
		t.Fatalf("return traffic: %v %+v", out, e)
	}
	if calls != 1 {
		t.Fatalf("decider called %d times", calls)
	}
	// data with payload from the originator: not TLS, counted
	data := tcp("10.21.0.2", "10.60.0.10", 40000, 80, netparse.TCPAck, []byte("GET / HTTP/1.0\r\n\r\n"))
	if out, e := tb.Handle(parse(t, data), data, peer, allow80); out != Pass || e.PacketsIn != 2 || e.BytesIn != uint64(len(syn)+len(data)) {
		t.Fatalf("data: %v %+v", out, e)
	}
	// denied flow: evaluated once, cached
	syn22 := tcp("10.21.0.2", "10.60.0.10", 40001, 22, netparse.TCPSyn, nil)
	for i := 0; i < 3; i++ {
		if out, _ := tb.Handle(parse(t, syn22), syn22, peer, allow80); out != Drop {
			t.Fatal("denied flow passed")
		}
	}
	if calls != 2 {
		t.Fatalf("deny not cached: %d calls", calls)
	}
	if len(events) != 2 || events[0].Type != EventOpen || events[1].Type != EventDeny {
		t.Fatalf("events %+v", events)
	}
	// FIN closes quickly
	fin := tcp("10.21.0.2", "10.60.0.10", 40000, 80, netparse.TCPFin|netparse.TCPAck, nil)
	tb.Handle(parse(t, fin), fin, peer, allow80)
	time.Sleep(5 * time.Millisecond)
	if n := tb.Expire(time.Now()); n != 2 {
		t.Fatalf("expired %d", n)
	}
	last := events[len(events)-1]
	if last.Type != EventClose || last.Entry.BytesIn == 0 || last.Reason != "idle" {
		t.Fatalf("close event %+v", last)
	}
	if tb.Len() != 0 {
		t.Fatal("table not empty")
	}
}

func TestSNIReevaluation(t *testing.T) {
	var events []Event
	tb := New(Timeouts{}, func(e Event) { events = append(events, e) })
	peer := Origin{Principal: "node-a"}
	noSecret := func(e *Entry) Result { return Result{Allow: e.SNI != "secret.lab"} }
	syn := tcp("10.21.0.2", "10.60.0.11", 40000, 443, netparse.TCPSyn, nil)
	if out, _ := tb.Handle(parse(t, syn), syn, peer, noSecret); out != Pass {
		t.Fatal("syn denied")
	}
	hello := clientHello("secret.lab")
	first := tcp("10.21.0.2", "10.60.0.11", 40000, 443, netparse.TCPAck, hello[:60])
	if out, _ := tb.Handle(parse(t, first), first, peer, noSecret); out != Pass {
		t.Fatal("partial hello dropped")
	}
	rest := tcp("10.21.0.2", "10.60.0.11", 40000, 443, netparse.TCPAck, hello[60:])
	out, e := tb.Handle(parse(t, rest), rest, peer, noSecret)
	if out != Reset || e.Allowed || e.SNI != "secret.lab" {
		t.Fatalf("sni: %v %+v", out, e)
	}
	if ev := events[len(events)-1]; ev.Type != EventDeny || !ev.Reset {
		t.Fatalf("deny event %+v", ev)
	}
	// later packets of the flow are dropped
	if out, _ := tb.Handle(parse(t, rest), rest, peer, noSecret); out != Drop {
		t.Fatal("denied flow passed after reset")
	}
	// an allowed name stays allowed and is recorded
	syn2 := tcp("10.21.0.2", "10.60.0.11", 40001, 443, netparse.TCPSyn, nil)
	tb.Handle(parse(t, syn2), syn2, peer, noSecret)
	h2 := tcp("10.21.0.2", "10.60.0.11", 40001, 443, netparse.TCPAck, clientHello("public.lab"))
	if out, e := tb.Handle(parse(t, h2), h2, peer, noSecret); out != Pass || e.SNI != "public.lab" {
		t.Fatalf("allowed sni: %v %+v", out, e)
	}
}

func TestDNSAndRelatedICMP(t *testing.T) {
	tb := New(Timeouts{}, nil)
	peer := Origin{Principal: "node-a"}
	q := append([]byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}, 4, 'e', 'v', 'i', 'l', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	pkt := udp("10.21.0.2", "10.60.0.53", 5353, 53, q)
	calls := 0
	dec := func(e *Entry) Result {
		calls++
		return Result{Allow: e.DNSName != "evil.com"}
	}
	if out, e := tb.Handle(parse(t, pkt), pkt, peer, dec); out != Drop || e.DNSName != "evil.com" || calls != 1 {
		t.Fatalf("dns: %v %+v calls %d", out, e, calls)
	}
	// allowed UDP flow and an ICMP error about it
	u := udp("10.21.0.2", "10.60.0.10", 5000, 6000, []byte("hi"))
	if out, _ := tb.Handle(parse(t, u), u, peer, dec); out != Pass {
		t.Fatal("udp denied")
	}
	// ICMP port unreachable from 10.60.0.10 quoting the UDP packet
	icmp := make([]byte, 28)
	icmp[0] = 0x45
	icmp[8], icmp[9] = 64, netparse.ProtoICMP
	copy(icmp[12:16], ip4("10.60.0.10"))
	copy(icmp[16:20], ip4("10.21.0.2"))
	icmp[20] = 3 // dest unreachable
	icmp = append(icmp, u...)
	binary.BigEndian.PutUint16(icmp[2:4], uint16(len(icmp)))
	if out, e := tb.Handle(parse(t, icmp), icmp, Origin{Local: true}, nil); out != Pass || e.Proto != netparse.ProtoUDP {
		t.Fatalf("related icmp: %v %+v", out, e)
	}
	// an unrelated ICMP error is a new flow of its own
	other := append([]byte{}, icmp...)
	binary.BigEndian.PutUint16(other[28+22:], 7000) // quoted dst port differs
	if out, e := tb.Handle(parse(t, other), other, peer, dec); out != Pass || e.Proto != netparse.ProtoICMP {
		t.Fatalf("unrelated icmp: %v %+v", out, e)
	}
}

func TestOverflow(t *testing.T) {
	tb := New(Timeouts{}, nil)
	allow := func(*Entry) Result { return Result{Allow: true} }
	for i := 0; i < MaxEntries; i++ {
		p := udp("10.21.0.2", "10.60.0.10", uint16(i), uint16(i>>16+1), nil)
		if i >= 1<<16 {
			p = udp("10.21.0.3", "10.60.0.10", uint16(i), 1, nil)
		}
		tb.Handle(parse(t, p), p, Origin{Principal: "x"}, allow)
	}
	p := udp("10.21.0.9", "10.60.0.10", 1, 1, nil)
	if out, _ := tb.Handle(parse(t, p), p, Origin{Principal: "x"}, allow); out != Drop || tb.Overflow() != 1 {
		t.Fatal("table accepted beyond MaxEntries")
	}
	if n := tb.CloseWhere(func(e *Entry) bool { return e.Origin.Principal == "x" }, "peer gone"); n != MaxEntries || tb.Len() != 0 {
		t.Fatalf("closed %d", n)
	}
}

// clientHello builds a minimal TLS 1.2-style ClientHello with a server_name.
func clientHello(name string) []byte {
	sni := []byte{0, 0, 0, 0, 0, 0, 0, byte(len(name) >> 8), byte(len(name))}
	sni = append(sni, name...)
	binary.BigEndian.PutUint16(sni[2:4], uint16(len(name)+5))
	binary.BigEndian.PutUint16(sni[4:6], uint16(len(name)+3))
	pad := make([]byte, 4+40) // an unknown extension to make it longer
	binary.BigEndian.PutUint16(pad[0:2], 0xfafa)
	binary.BigEndian.PutUint16(pad[2:4], 40)
	ext := append(pad, sni...)
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                            // session id
	body = append(body, 0, 2, 0x13, 0x01)             // cipher suites
	body = append(body, 1, 0)                         // compression
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return rec
}

func TestReevaluate(t *testing.T) {
	var events []Event
	tb := New(Timeouts{}, func(e Event) { events = append(events, e) })
	peer := Origin{Principal: "node-a"}
	allow := func(*Entry) Result { return Result{Allow: true} }
	for _, port := range []uint16{80, 22} {
		p := tcp("10.21.0.2", "10.60.0.10", 40000+port, port, netparse.TCPSyn, nil)
		tb.Handle(parse(t, p), p, peer, allow)
	}
	local := tcp("10.60.0.10", "10.21.0.2", 1, 2, netparse.TCPSyn, nil)
	tb.Handle(parse(t, local), local, Origin{Local: true}, nil)
	only80 := func(e *Entry) Result { return Result{Allow: e.Target.Port() == 80} }
	if n := tb.Reevaluate(only80); n != 1 {
		t.Fatalf("closed %d", n)
	}
	p22 := tcp("10.21.0.2", "10.60.0.10", 40022, 22, netparse.TCPAck, nil)
	if out, _ := tb.Handle(parse(t, p22), p22, peer, only80); out != Drop {
		t.Fatal("re-denied flow passed")
	}
	p80 := tcp("10.21.0.2", "10.60.0.10", 40080, 80, netparse.TCPAck, nil)
	if out, _ := tb.Handle(parse(t, p80), p80, peer, only80); out != Pass {
		t.Fatal("still-allowed flow dropped")
	}
	if out, _ := tb.Handle(parse(t, local), local, Origin{Local: true}, nil); out != Pass {
		t.Fatal("local flow affected")
	}
	last := events[len(events)-1]
	if last.Type != EventClose || last.Reason != "policy changed" || events[len(events)-2].Type != EventDeny {
		t.Fatalf("%+v", events)
	}
}
