package netparse

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// clientHelloRecord is realClientHello for fuzz seeds: the first TLS record
// crypto/tls sends for name.
func clientHelloRecord(tb testing.TB, name string) []byte {
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

// segmentValid reports whether the TCP checksum of pkt verifies over
// everything behind the IP header.
func segmentValid(h Header, pkt []byte) bool {
	var l4 int
	var pseudo []byte
	switch h.Version {
	case 4:
		l4 = int(pkt[0]&0x0f) * 4
		pseudo = make([]byte, 12)
		copy(pseudo[0:8], pkt[12:20])
		pseudo[9] = ProtoTCP
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(pkt)-l4))
	case 6:
		l4 = 40
		pseudo = make([]byte, 40)
		copy(pseudo[0:32], pkt[8:40])
		binary.BigEndian.PutUint32(pseudo[32:], uint32(len(pkt)-l4))
		pseudo[39] = ProtoTCP
	}
	return Checksum(pkt[l4:], ^Checksum(pseudo, 0)) == 0
}

// ClampMSS rewrites packets in place on every hop: it must stay inside the
// options it walks, and a segment whose checksum verified still verifies.
func FuzzClampMSS(f *testing.F) {
	f.Add(syn([]byte{2, 4, 0x05, 0xb4}, TCPSyn), uint16(1240))
	f.Add(syn([]byte{1, 2, 4, 0x05, 0xb4, 1, 1, 1}, TCPSyn|TCPAck), uint16(1240))
	f.Add(syn([]byte{1, 1, 4, 2, 2, 4, 0x23, 0x28, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7}, TCPSyn), uint16(1220))
	f.Add(syn([]byte{3, 3, 7, 2, 4, 0xff, 0xff}, TCPSyn), uint16(0))
	f.Add(syn(nil, TCPSyn), uint16(1240))
	f.Fuzz(func(t *testing.T, pkt []byte, mss uint16) {
		h, ok := Parse(pkt)
		if !ok {
			return
		}
		valid := h.Proto == ProtoTCP && h.Payload >= 0 && !h.Fragment() && segmentValid(h, pkt)
		before := append([]byte(nil), pkt...)
		if !ClampMSS(h, pkt, mss) {
			if !bytes.Equal(before, pkt) {
				t.Fatal("unchanged packet was modified")
			}
			return
		}
		if len(pkt) != len(before) {
			t.Fatal("length changed")
		}
		l4 := 40
		if h.Version == 4 {
			l4 = int(pkt[0]&0x0f) * 4
		}
		for i := range pkt {
			inOpts := i >= l4+20 && i < h.Payload
			inSum := i == l4+16 || i == l4+17
			if pkt[i] != before[i] && !inOpts && !inSum {
				t.Fatalf("byte %d outside the options changed", i)
			}
		}
		if valid && !segmentValid(h, pkt) {
			t.Fatalf("checksum broken by the clamp\nbefore %x\nafter  %x", before, pkt)
		}
	})
}

func FuzzFragNeeded(f *testing.F) {
	f.Add(syn([]byte{2, 4, 0x05, 0xb4}, TCPSyn), 1280)
	f.Add(v4("10.0.0.1", "10.0.0.2", ProtoICMP, []byte{8, 0, 0, 0, 0, 1, 0, 1}), 1100)
	f.Add(v4("10.0.0.1", "10.0.0.2", ProtoICMP, []byte{3, 4, 0, 0}), 1100)
	f.Add([]byte{0x46, 0, 0, 24, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 1, 1, 1, 1}, 0)
	f.Fuzz(func(t *testing.T, pkt []byte, mtu int) {
		out := FragNeeded(pkt, mtu)
		if out == nil {
			return
		}
		ihl := int(pkt[0]&0x0f) * 4
		if len(out) != 28+min(len(pkt), ihl+8) {
			t.Fatalf("answer of %d bytes to a packet of %d with ihl %d", len(out), len(pkt), ihl)
		}
		if int(binary.BigEndian.Uint16(out[2:])) != len(out) || Checksum(out[:20], 0) != 0 || Checksum(out[20:], 0) != 0 {
			t.Fatal("length or checksums of the answer are wrong")
		}
		if out[20] != 3 || out[21] != 4 || binary.BigEndian.Uint16(out[26:]) != uint16(mtu) {
			t.Fatal("not a fragmentation-needed answer")
		}
		if !bytes.Equal(out[28:], pkt[:len(out)-28]) {
			t.Fatal("quote is not the start of the packet")
		}
	})
}

func FuzzDNSAnswer(f *testing.F) {
	f.Add(msg(0x8180, "example.com", a("93.184.216.34", 300)))
	f.Add(msg(0x8180, "www.example.com", cname("example.com", 60), a("93.184.216.34", 300), a("2606:2800:220:1::1", 30)))
	f.Add(msg(0x8183, "nx.example.com"))
	f.Add(msg(0x8380, "tc.example.com", a("10.0.0.1", 1)))
	f.Fuzz(func(t *testing.T, b []byte) {
		name, addrs, ttl, ok := DNSAnswer(b)
		if !ok {
			if name != "" || addrs != nil || ttl != 0 {
				t.Fatal("result without ok")
			}
			return
		}
		if name == "" || len(name) > 253 || len(addrs) == 0 || len(addrs) > maxDNSAnswers || ttl < 0 {
			t.Fatalf("name %q, %d addresses, ttl %v", name, len(addrs), ttl)
		}
		for _, a := range addrs {
			if !a.IsValid() {
				t.Fatal("invalid address")
			}
		}
	})
}

// Every prefix of a real ClientHello asks for more or finds the same name:
// the flow table feeds the parser segment by segment.
func FuzzClientHelloSNIPrefix(f *testing.F) {
	f.Add(clientHelloRecord(f, "Nodes.BG.example.com"), 100)
	f.Add(clientHelloRecord(f, "a.b"), 7)
	f.Fuzz(func(t *testing.T, b []byte, cut int) {
		full, res := ClientHelloSNI(b)
		if res == SNIFound && (full == "" || len(full) > 253 || !validHostname(full)) {
			t.Fatalf("bad name %q", full)
		}
		if cut < 0 || cut > len(b) {
			return
		}
		name, pres := ClientHelloSNI(b[:cut])
		if res == SNIFound && pres != SNINeedMore && (pres != SNIFound || name != full) {
			t.Fatalf("prefix of %d yields %q/%d, the whole %q", cut, name, pres, full)
		}
	})
}
