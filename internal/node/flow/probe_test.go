package flow

import (
	"encoding/binary"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
)

// A permit that names a TLS server cannot match a SYN: no name yet. The
// flow table lets the handshake through and decides on the ClientHello.
func TestPermitBySNIDecidesOnTheClientHello(t *testing.T) {
	var events []Event
	tb := New(Timeouts{}, func(e Event) { events = append(events, e) })
	nas := Origin{Principal: "nas"}
	onlyMyIP := func(e *Entry) Result {
		if e.SNI == "myip.wtf" {
			return Result{Allow: true, Policies: []string{"myip-check"}}
		}
		return Result{PermitBySNI: e.SNI == ""}
	}
	flow := func(sport uint16, flags uint8, payload []byte) []byte {
		return tcp("10.25.0.5", "104.19.192.174", sport, 443, flags, payload)
	}
	reply := func(sport uint16, flags uint8, payload []byte) []byte {
		return tcp("104.19.192.174", "10.25.0.5", 443, sport, flags, payload)
	}
	handle := func(p []byte) (Outcome, *Entry) { return tb.Handle(parse(t, p), p, nas, onlyMyIP) }

	// permitted name: handshake, hello, data
	if out, e := handle(flow(40000, netparse.TCPSyn, nil)); out != Pass || !e.Probing() || e.Allowed {
		t.Fatalf("syn: %v %+v", out, e)
	}
	if out, _ := handle(reply(40000, netparse.TCPSyn|netparse.TCPAck, nil)); out != Pass {
		t.Fatal("syn-ack")
	}
	if out, _ := handle(flow(40000, netparse.TCPAck, nil)); out != Pass {
		t.Fatal("ack")
	}
	if len(events) != 0 {
		t.Fatalf("nothing to report during the handshake: %+v", events)
	}
	out, e := handle(flow(40000, netparse.TCPAck, clientHello("myip.wtf")))
	if out != Pass || !e.Allowed || e.Probing() || e.SNI != "myip.wtf" {
		t.Fatalf("hello: %v %+v", out, e)
	}
	if len(events) != 1 || events[0].Type != EventOpen || events[0].Entry.SNI != "myip.wtf" {
		t.Fatalf("open event with the name: %+v", events)
	}
	if out, _ := handle(reply(40000, netparse.TCPAck, []byte("server hello"))); out != Pass {
		t.Fatal("data of the permitted flow")
	}

	// another name: the hello is not forwarded, both ends get a reset
	handle(flow(40001, netparse.TCPSyn, nil))
	handle(reply(40001, netparse.TCPSyn|netparse.TCPAck, nil))
	out, e = handle(flow(40001, netparse.TCPAck, clientHello("evil.example")))
	if out != Reset || e.Allowed || e.Probing() {
		t.Fatalf("other name: %v %+v", out, e)
	}
	if ev := events[len(events)-1]; ev.Type != EventDeny || !ev.Reset || ev.Entry.SNI != "evil.example" {
		t.Fatalf("deny event names the server: %+v", ev)
	}
	if out, _ := handle(flow(40001, netparse.TCPAck, []byte("more"))); out != Drop {
		t.Fatal("a denied flow stays denied")
	}

	// not TLS at all: reset on the first payload
	handle(flow(40002, netparse.TCPSyn, nil))
	if out, _ := handle(flow(40002, netparse.TCPAck, []byte("GET / HTTP/1.0\r\n"))); out != Reset {
		t.Fatal("plain text is no TLS client hello")
	}
	// the server speaks first: nothing to decide on, reset
	handle(flow(40003, netparse.TCPSyn, nil))
	if out, _ := handle(reply(40003, netparse.TCPAck, []byte("220 banner"))); out != Reset {
		t.Fatal("server payload before a hello")
	}
	// a plain deny is not probed
	if out, e := tb.Handle(parse(t, flow(40004, netparse.TCPSyn, nil)), flow(40004, netparse.TCPSyn, nil), nas, func(*Entry) Result { return Result{} }); out != Drop || e.Probing() {
		t.Fatal("a deny without an SNI permit in scope is a deny")
	}
}

// The name decided on is the name the server reads. A sender cannot show
// the table one ClientHello and the server another: by a segment the
// server drops (a bad checksum) in front of the real one, by sending the
// same range again with other bytes, or by a segment past a gap.
func TestTheNameIsReadAsTheServerReadsIt(t *testing.T) {
	tb := New(Timeouts{}, nil)
	nas := Origin{Principal: "nas"}
	byName := func(e *Entry) Result {
		switch e.SNI {
		case "myip.wtf":
			return Result{Allow: true}
		case "":
			return Result{PermitBySNI: true}
		}
		return Result{}
	}
	const cl, srv = "10.25.0.5", "104.19.192.174"
	handle := func(p []byte) (Outcome, *Entry) { return tb.Handle(parse(t, p), p, nas, byName) }
	open := func(sport uint16) {
		handle(tcp(cl, srv, sport, 443, netparse.TCPSyn, nil))
		handle(tcp(srv, cl, 443, sport, netparse.TCPSyn|netparse.TCPAck, nil))
	}
	good, evil := clientHello("myip.wtf"), clientHello("evil.example")
	if len(good) != len(evil)-4 {
		t.Fatalf("hello sizes %d %d", len(good), len(evil))
	}

	// a split hello for the permitted name, then "retransmissions" of its
	// first half with other bytes: never forwarded
	open(41000)
	half := len(good) / 2
	if out, _ := handle(tcpSeq(cl, srv, 41000, 443, netparse.TCPAck, 1001, good[:half])); out != Drop {
		t.Fatal("first half of a hello is held back while probing")
	}
	out, e := handle(tcpSeq(cl, srv, 41000, 443, netparse.TCPAck, 1001+uint32(half), good[half:]))
	if out != Pass || !e.Allowed || e.SNI != "myip.wtf" {
		t.Fatalf("second half: %v %+v", out, e)
	}
	if out, _ := handle(tcpSeq(cl, srv, 41000, 443, netparse.TCPAck, 1001, evil[:half])); out != Drop {
		t.Fatal("other bytes for the range the name was read from reached the server")
	}
	if out, _ := handle(tcpSeq(cl, srv, 41000, 443, netparse.TCPAck, 1001, good[:half])); out != Pass {
		t.Fatal("the true retransmission must pass")
	}
	// once the server acknowledged the hello, its TCP takes nothing for
	// that range any more: the bytes are let go
	ack := tcpSeq(srv, cl, 443, 41000, netparse.TCPAck, 1001, nil)
	binary.BigEndian.PutUint32(ack[28:32], 1001+uint32(len(good)-1))
	handle(ack)
	if e.sniBuf == nil {
		t.Fatal("let go before the last byte was acknowledged")
	}
	binary.BigEndian.PutUint32(ack[28:32], 1001+uint32(len(good)))
	handle(ack)
	if e.sniBuf != nil {
		t.Fatal("the hello is acknowledged; nothing to keep")
	}

	// a segment the server will drop, read first: the real one in its
	// place differs and does not pass
	open(41001)
	if out, _ := handle(tcpSeq(cl, srv, 41001, 443, netparse.TCPAck, 1001, good)); out != Pass {
		t.Fatal("the permitted hello")
	}
	if out, _ := handle(tcpSeq(cl, srv, 41001, 443, netparse.TCPAck, 1001, evil)); out != Drop {
		t.Fatal("a second hello at the same place reached the server")
	}

	// past a gap while the name is open: held back, so the server cannot
	// have bytes the table never read
	open(41002)
	if out, _ := handle(tcpSeq(cl, srv, 41002, 443, netparse.TCPAck, 1001+uint32(half), evil[half:])); out != Drop {
		t.Fatal("a segment after a gap passed while the name is open")
	}
}
