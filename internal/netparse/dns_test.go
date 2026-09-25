package netparse

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// msg builds a DNS message: the question, then the records given as
// (type, ttl, rdata). Record names are the compression pointer to the
// question, the way every resolver writes them.
func msg(flags uint16, name string, answers ...rr) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], 0x1234)
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint16(b[4:6], 1)
	binary.BigEndian.PutUint16(b[6:8], uint16(len(answers)))
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, 1) // QTYPE A
	b = binary.BigEndian.AppendUint16(b, 1) // QCLASS IN
	for _, a := range answers {
		b = append(b, 0xc0, 12) // the question's name
		b = binary.BigEndian.AppendUint16(b, a.typ)
		b = binary.BigEndian.AppendUint16(b, 1) // IN
		b = binary.BigEndian.AppendUint32(b, a.ttl)
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.data)))
		b = append(b, a.data...)
	}
	return b
}

type rr struct {
	typ  uint16
	ttl  uint32
	data []byte
}

func a(ip string, ttl uint32) rr {
	addr := netip.MustParseAddr(ip)
	typ := uint16(1)
	if addr.Is6() {
		typ = 28
	}
	return rr{typ: typ, ttl: ttl, data: addr.AsSlice()}
}

func cname(target string, ttl uint32) rr {
	var d []byte
	for _, l := range strings.Split(target, ".") {
		d = append(d, byte(len(l)))
		d = append(d, l...)
	}
	return rr{typ: 5, ttl: ttl, data: append(d, 0)}
}

func TestDNSAnswerReadsAddressesAndTheShortestTTL(t *testing.T) {
	name, addrs, ttl, ok := DNSAnswer(msg(0x8180, "API.github.com", cname("github.map.example", 300), a("140.82.121.4", 120), a("2606:50c0::1", 60)))
	if !ok {
		t.Fatal("a plain answer was not read")
	}
	if name != "api.github.com" {
		t.Fatalf("name %q", name)
	}
	if len(addrs) != 2 || addrs[0].String() != "140.82.121.4" || addrs[1].String() != "2606:50c0::1" {
		t.Fatalf("addresses %v", addrs)
	}
	if ttl != 60*time.Second {
		t.Fatalf("ttl %s", ttl)
	}
}

func TestDNSAnswerRefusesWhatItMustNotLearn(t *testing.T) {
	cases := map[string][]byte{
		"a query":            msg(0x0100, "api.github.com", a("140.82.121.4", 60)),
		"an error":           msg(0x8183, "api.github.com"),
		"no address":         msg(0x8180, "api.github.com", cname("github.map.example", 300)),
		"truncated":          msg(0x8380, "api.github.com", a("140.82.121.4", 60)),
		"too short":          {1, 2, 3},
		"cut off mid-record": msg(0x8180, "api.github.com", a("140.82.121.4", 60))[:30],
	}
	for what, b := range cases {
		if _, _, _, ok := DNSAnswer(b); ok {
			t.Fatalf("%s was read as an answer", what)
		}
	}
	// a query is still a query, and DNSQueryName still only reads those
	if n, ok := DNSQueryName(msg(0x0100, "api.github.com")); !ok || n != "api.github.com" {
		t.Fatalf("query name %q %v", n, ok)
	}
	if _, ok := DNSQueryName(msg(0x8180, "api.github.com", a("140.82.121.4", 60))); ok {
		t.Fatal("a response is not a question")
	}
}

// A flow a permit opened for a question carries questions: a message with
// records in it, another opcode or a dot hidden inside a label is not one.
func TestDNSQueryIsAPlainQuestion(t *testing.T) {
	q := msg(0x0100, "api.github.com")
	id, name, ok := DNSQuery(q)
	if !ok || id != 0x1234 || name != "api.github.com" {
		t.Fatalf("id %x name %q ok %v", id, name, ok)
	}
	withEDNS := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(withEDNS[10:12], 1)
	if _, _, ok := DNSQuery(withEDNS); !ok {
		t.Fatal("one additional record (EDNS) is a normal query")
	}
	cases := map[string][]byte{
		"a query with an answer": msg(0x0100, "api.github.com", a("140.82.121.4", 60)),
		"a notify":               msg(0x2100, "api.github.com"),
		"two additional records": func() []byte { b := append([]byte(nil), q...); binary.BigEndian.PutUint16(b[10:12], 2); return b }(),
		"a dot inside a label":   msg(0x0100, "x.github.com"),
	}
	// "x.github" as one label, then "com": reads as x.github.com
	dotted := cases["a dot inside a label"]
	copy(dotted[12:], []byte{8, 'x', '.', 'g', 'i', 't', 'h', 'u', 'b', 3, 'c', 'o', 'm', 0})
	cases["a dot inside a label"] = dotted[:12+14+4]
	for what, b := range cases {
		if _, _, ok := DNSQuery(b); ok {
			t.Fatalf("%s was read as a query", what)
		}
	}
	if rid, ok := DNSResponseID(msg(0x8180, "api.github.com", a("140.82.121.4", 60))); !ok || rid != 0x1234 {
		t.Fatalf("response id %x %v", rid, ok)
	}
	if _, ok := DNSResponseID(q); ok {
		t.Fatal("a query has no response id")
	}
}
