package flow

import (
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
