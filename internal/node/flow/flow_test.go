package flow

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
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
	// two questions to the policies: the address alone, then the name
	if out, e := tb.Handle(parse(t, pkt), pkt, peer, dec); out != Drop || e.DNSName != "evil.com" || calls != 2 {
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
	// an error about that flow addressed to anyone but its sender is no
	// error about it
	elsewhere := append([]byte{}, icmp...)
	copy(elsewhere[16:20], ip4("10.60.0.99"))
	if out, e := tb.Handle(parse(t, elsewhere), elsewhere, peer, dec); out != Pass || e.Proto != netparse.ProtoICMP {
		t.Fatalf("icmp error to a third host rode the flow: %v %+v", out, e)
	}
	// nor is a redirect
	redirect := append([]byte{}, icmp...)
	redirect[20] = 5
	if _, e := tb.Handle(parse(t, redirect), redirect, Origin{Local: true}, nil); e == nil || e.Proto != netparse.ProtoICMP {
		t.Fatalf("a redirect passed as part of the flow: %+v", e)
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
	peers := MaxEntries / MaxPerPeer
	for i := 0; i < MaxEntries; i++ {
		principal := transport.DeviceID(fmt.Sprintf("p%d", i%peers))
		p := udp("10.21.0.2", "10.60.0.10", uint16(i), uint16(i>>16+1), nil)
		tb.Handle(parse(t, p), p, Origin{Principal: principal}, allow)
	}
	if tb.Len() != MaxEntries {
		t.Fatalf("%d flows", tb.Len())
	}
	p := udp("10.21.0.9", "10.60.0.10", 1, 1, nil)
	if out, _ := tb.Handle(parse(t, p), p, Origin{Principal: "late"}, allow); out != Drop || tb.Overflow() != 1 {
		t.Fatal("table accepted beyond MaxEntries")
	}
	if n := tb.CloseWhere(func(e *Entry) bool { return true }, "peer gone"); n != MaxEntries || tb.Len() != 0 {
		t.Fatalf("closed %d", n)
	}
}

// One sender cannot take the table from the others.
func TestOnePeerCannotFillTheTable(t *testing.T) {
	tb := New(Timeouts{}, nil)
	allow := func(*Entry) Result { return Result{Allow: true} }
	for i := 0; i < MaxPerPeer+10; i++ {
		p := udp("10.21.0.2", "10.60.0.10", uint16(i), 9, nil)
		tb.Handle(parse(t, p), p, Origin{Principal: "greedy"}, allow)
	}
	if tb.Len() != MaxPerPeer || tb.Overflow() != 10 {
		t.Fatalf("%d flows, %d refused", tb.Len(), tb.Overflow())
	}
	p := udp("10.21.0.3", "10.60.0.10", 1, 9, nil)
	if out, _ := tb.Handle(parse(t, p), p, Origin{Principal: "other"}, allow); out != Pass {
		t.Fatal("another peer was refused")
	}
	for i := 0; i < MaxLocal+1; i++ {
		p := udp("10.60.0.10", "10.21.0.7", uint16(i), 7, nil)
		tb.Handle(parse(t, p), p, Origin{Local: true}, nil)
	}
	if tb.Len() != MaxPerPeer+1+MaxLocal {
		t.Fatalf("local flows: %d in the table", tb.Len())
	}
	// entries that leave give their share back
	tb.CloseWhere(func(e *Entry) bool { return e.Origin.Principal == "greedy" }, "gone")
	p = udp("10.21.0.2", "10.60.0.10", 1, 10, nil)
	if out, _ := tb.Handle(parse(t, p), p, Origin{Principal: "greedy"}, allow); out != Pass {
		t.Fatal("the quota was not given back")
	}
}

// A SYN nobody answers holds its entry for a minute, not for the lifetime
// of a TCP connection.
func TestUnansweredSYNExpiresEarly(t *testing.T) {
	tb := New(Timeouts{}, nil)
	allow := func(*Entry) Result { return Result{Allow: true} }
	syn := tcp("10.21.0.2", "10.60.0.10", 40000, 22, netparse.TCPSyn, nil)
	tb.Handle(parse(t, syn), syn, Origin{Principal: "node-a"}, allow)
	answered := tcp("10.21.0.2", "10.60.0.10", 40001, 22, netparse.TCPSyn, nil)
	tb.Handle(parse(t, answered), answered, Origin{Principal: "node-a"}, allow)
	synack := tcp("10.60.0.10", "10.21.0.2", 22, 40001, netparse.TCPSyn|netparse.TCPAck, nil)
	tb.Handle(parse(t, synack), synack, Origin{Local: true}, nil)
	if n := tb.Expire(time.Now().Add(2 * time.Minute)); n != 1 || tb.Len() != 1 {
		t.Fatalf("expired %d, %d left", n, tb.Len())
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
	body = append(body, 0)                // session id
	body = append(body, 0, 2, 0x13, 0x01) // cipher suites
	body = append(body, 1, 0)             // compression
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

// The tail of a connection the table no longer knows (a server's late
// retransmission through the exit node, 5 s after the client closed) is
// dropped without a "deny" in the log: reported, it reads as "the hub tried
// to connect to this node". A real attempt to connect still is reported, and
// a permitted connection still survives a reconnect.
func TestStrayTCPSegmentsAreNotReportedAsDenied(t *testing.T) {
	var denies int
	tb := New(Timeouts{}, func(e Event) {
		if e.Type == EventDeny {
			denies++
		}
	})
	hub := Origin{Principal: "hub"}
	nothing := func(*Entry) Result { return Result{} }
	for i, flags := range []uint8{netparse.TCPAck, netparse.TCPAck | netparse.TCPFin, netparse.TCPRst, netparse.TCPSyn | netparse.TCPAck} {
		p := tcp("140.82.112.26", "10.25.0.1", 443, uint16(65000+i), flags, nil)
		if out, _ := tb.Handle(parse(t, p), p, hub, nothing); out != Drop {
			t.Fatalf("flags %#x passed", flags)
		}
	}
	if denies != 0 || tb.Strays() != 4 {
		t.Fatalf("denies reported %d, strays %d", denies, tb.Strays())
	}
	syn := tcp("140.82.112.26", "10.25.0.1", 443, 22, netparse.TCPSyn, nil)
	if out, _ := tb.Handle(parse(t, syn), syn, hub, nothing); out != Drop || denies != 1 {
		t.Fatalf("a connection attempt must be reported: %v, %d", out, denies)
	}
	mid := tcp("10.25.0.1", "10.20.1.33", 50000, 9201, netparse.TCPAck, []byte("x"))
	if out, e := tb.Handle(parse(t, mid), mid, Origin{Principal: "mac"}, func(*Entry) Result { return Result{Allow: true} }); out != Pass || !e.Allowed {
		t.Fatal("a permitted connection from before a reconnect must go on")
	}
}

// A server that sends without the DF bit gets its packets fragmented on the
// way into the tunnel (seen with www.heise.de behind an exit node). The rest
// of a packet has no ports: it follows its first fragment or it is dropped.
func TestFragmentsFollowTheirFirstFragment(t *testing.T) {
	var events []EventType
	tb := New(Timeouts{}, func(e Event) { events = append(events, e.Type) })
	allow := func(*Entry) Result { return Result{Allow: true} }
	mac, hub := Origin{Local: true}, Origin{Principal: "hub"}

	syn := tcp("10.25.0.1", "193.99.144.85", 50273, 443, netparse.TCPSyn, nil)
	if out, _ := tb.Handle(parse(t, syn), syn, mac, allow); out != Pass {
		t.Fatal("syn")
	}
	frag := func(id uint16, offset int, more bool, payload int) []byte {
		p := tcp("193.99.144.85", "10.25.0.1", 443, 50273, netparse.TCPAck, make([]byte, payload))
		binary.BigEndian.PutUint16(p[4:6], id)
		ff := uint16(offset / 8)
		if more {
			ff |= 0x2000
		}
		binary.BigEndian.PutUint16(p[6:8], ff)
		return p
	}
	first, rest := frag(49804, 0, true, 1168), frag(49804, 1208, false, 32)
	out, e := tb.Handle(parse(t, first), first, hub, allow)
	if out != Pass {
		t.Fatal("first fragment of a permitted connection")
	}
	out, e2 := tb.Handle(parse(t, rest), rest, hub, allow)
	if out != Pass || e2 != e {
		t.Fatalf("the rest must pass with the flow of its first fragment: %v", out)
	}
	if e.BytesOut != uint64(len(first)+len(rest)) {
		t.Fatalf("both fragments count for the flow: %d", e.BytesOut)
	}
	if tb.Len() != 1 {
		t.Fatalf("a fragment opened a flow of its own: %d flows", tb.Len())
	}
	// the packet is complete: the same id does not pass a second time
	if out, _ := tb.Handle(parse(t, rest), rest, hub, allow); out != Drop {
		t.Fatal("a fragment after the last one passed")
	}
	// no first fragment, or one that starts inside the transport header
	for _, p := range [][]byte{frag(7, 1208, false, 32), frag(49805, 8, false, 32)} {
		if p[5] == 0xcd { // 49805: give it a first fragment that passed
			f := frag(49805, 0, true, 1168)
			tb.Handle(parse(t, f), f, hub, allow)
		}
		if out, _ := tb.Handle(parse(t, p), p, hub, allow); out != Drop {
			t.Fatalf("fragment %x passed", p[4:8])
		}
	}
	for _, ev := range events {
		if ev == EventDeny {
			t.Fatal("a dropped fragment is nothing to report")
		}
	}
	if tb.Strays() != 3 {
		t.Fatalf("strays %d", tb.Strays())
	}
}

// dnsMsg builds a query (qr=false) or an answer with one A record.
func dnsMsg(name string, answer string) []byte {
	return dnsMsgID(0x1234, name, answer)
}

func dnsMsgID(id uint16, name string, answer string) []byte {
	b := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	if answer != "" {
		b[2], b[3] = 0x81, 0x80
		b[7] = 1
	}
	for _, l := range splitDots(name) {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, 0, 1, 0, 1)
	if answer != "" {
		b = append(b, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		b = append(b, ip4(answer)...)
	}
	return b
}

func splitDots(s string) []string {
	var out []string
	for len(s) > 0 {
		i := 0
		for i < len(s) && s[i] != '.' {
			i++
		}
		out = append(out, s[:i])
		if i == len(s) {
			break
		}
		s = s[i+1:]
	}
	return out
}

// The Learner hears the answer to every query that passed, with the name of
// that query: one socket may ask several names.
func TestLearnerSeesTheAnswersOfAnAllowedFlow(t *testing.T) {
	tb := New(Timeouts{}, nil)
	peer := Origin{Principal: "node-a"}
	type learned struct {
		peer, name string
		addrs      int
		ttl        time.Duration
	}
	var got []learned
	tb.SetLearner(func(e *Entry, name string, addrs []netip.Addr, ttl time.Duration) {
		got = append(got, learned{string(e.Origin.Principal), name, len(addrs), ttl})
	})
	// permitted by name only: the resolver's address alone is not
	allow := func(e *Entry) Result { return Result{Allow: e.DNSName != "" && e.DNSName != "evil.com"} }

	q := dnsMsg("api.github.com", "")
	pkt := udp("10.21.0.2", "10.60.0.53", 5353, 53, q)
	if out, _ := tb.Handle(parse(t, pkt), pkt, peer, allow); out != Pass {
		t.Fatal("the query was denied")
	}
	if len(got) != 0 {
		t.Fatalf("a question teaches nothing: %+v", got)
	}
	ans := udp("10.60.0.53", "10.21.0.2", 53, 5353, dnsMsg("api.github.com", "140.82.121.4"))
	if out, _ := tb.Handle(parse(t, ans), ans, Origin{Local: true}, nil); out != Pass {
		t.Fatal("the answer was dropped")
	}
	if len(got) != 1 || got[0] != (learned{"node-a", "api.github.com", 1, time.Minute}) {
		t.Fatalf("learned %+v", got)
	}
	// the same answer again: its query was answered already
	if out, _ := tb.Handle(parse(t, ans), ans, Origin{Local: true}, nil); out != Drop || len(got) != 1 {
		t.Fatalf("a second answer to one query: %v, learned %+v", out, got)
	}
	// an answer nobody asked for passes nowhere and teaches nothing
	ans2 := udp("10.60.0.53", "10.21.0.2", 53, 5353, dnsMsgID(0x4242, "other.example", "10.0.0.9"))
	if out, _ := tb.Handle(parse(t, ans2), ans2, Origin{Local: true}, nil); out != Drop || len(got) != 1 {
		t.Fatalf("an unsolicited answer: %v, learned %+v", out, got)
	}
	// a second question over the same socket: its answer, under its ID
	q2 := udp("10.21.0.2", "10.60.0.53", 5353, 53, dnsMsgID(0x4242, "other.example", ""))
	if out, _ := tb.Handle(parse(t, q2), q2, peer, allow); out != Pass {
		t.Fatal("the second question was denied")
	}
	// an answer under that ID for another question is not its answer
	wrong := udp("10.60.0.53", "10.21.0.2", 53, 5353, dnsMsgID(0x4242, "api.github.com", "10.0.0.66"))
	if out, _ := tb.Handle(parse(t, wrong), wrong, Origin{Local: true}, nil); out != Drop || len(got) != 1 {
		t.Fatalf("an answer to another question: %v, learned %+v", out, got)
	}
	tb.Handle(parse(t, ans2), ans2, Origin{Local: true}, nil)
	if len(got) != 2 || got[1].name != "other.example" {
		t.Fatalf("learned %+v", got)
	}
	// a refused question on the same socket is dropped alone
	q3 := udp("10.21.0.2", "10.60.0.53", 5353, 53, dnsMsgID(0x5555, "evil.com", ""))
	if out, _ := tb.Handle(parse(t, q3), q3, peer, allow); out != Drop {
		t.Fatal("evil.com passed on a socket that asked a permitted name before")
	}
	if out, _ := tb.Handle(parse(t, q2), q2, peer, allow); out != Pass {
		t.Fatal("the socket is still good for permitted names")
	}
	// data that is no query rides no permitted name
	junk := udp("10.21.0.2", "10.60.0.53", 5353, 53, []byte("GET / HTTP/1.1\r\n\r\n"))
	if out, _ := tb.Handle(parse(t, junk), junk, peer, allow); out != Drop {
		t.Fatal("non-DNS data passed on a flow opened by a question")
	}

	// a denied flow teaches nothing, however its answer looks
	den := udp("10.21.0.2", "10.60.0.53", 5354, 53, dnsMsg("evil.com", ""))
	if out, _ := tb.Handle(parse(t, den), den, peer, allow); out != Drop {
		t.Fatal("evil.com was allowed")
	}
	dans := udp("10.60.0.53", "10.21.0.2", 53, 5354, dnsMsg("evil.com", "10.0.0.66"))
	tb.Handle(parse(t, dans), dans, Origin{Local: true}, nil)
	if len(got) != 2 {
		t.Fatalf("a denied flow taught something: %+v", got)
	}
}

// A ClientHello that never completes within MaxClientHello ends the
// inspection, and the bytes gathered for it go with it: an allowed flow
// lives for half an hour, and a peer can open many.
func TestSNIBufferReleasedWhenInspectionGivesUp(t *testing.T) {
	tb := New(Timeouts{}, nil)
	peer := Origin{Principal: "node-a"}
	allow := func(*Entry) Result { return Result{Allow: true} }
	syn := tcp("10.21.0.2", "10.60.0.11", 40000, 443, netparse.TCPSyn, nil)
	tb.Handle(parse(t, syn), syn, peer, allow)
	// a handshake header that announces more than the table buffers
	seg := append([]byte{0x16, 0x03, 0x01, 0x40, 0x00, 0x01, 0x00, 0x3f, 0xfb, 0x03, 0x03}, make([]byte, 1200)...)
	var e *Entry
	for i := 0; i*len(seg) <= netparse.MaxClientHello; i++ {
		p := tcp("10.21.0.2", "10.60.0.11", 40000, 443, netparse.TCPAck, seg)
		var out Outcome
		if out, e = tb.Handle(parse(t, p), p, peer, allow); out != Pass {
			t.Fatalf("segment %d: %v", i, out)
		}
		seg = make([]byte, 1200)
	}
	if !e.sniDone || e.sniBuf != nil {
		t.Fatalf("inspection done %v, %d bytes still buffered", e.sniDone, len(e.sniBuf))
	}
}
