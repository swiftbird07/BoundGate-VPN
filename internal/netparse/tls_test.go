package netparse

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
)

// realClientHello captures the ClientHello Go's crypto/tls sends for name.
func realClientHello(t *testing.T, name string) []byte {
	t.Helper()
	c, s := net.Pipe()
	defer s.Close()
	go func() {
		cl := tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true})
		_ = cl.Handshake()
		c.Close()
	}()
	buf := make([]byte, 8192)
	var out []byte
	for {
		n, err := s.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil || len(out) >= 5 && len(out) >= 5+int(binary.BigEndian.Uint16(out[3:5])) {
			break
		}
	}
	return out
}

func TestClientHelloSNI(t *testing.T) {
	hello := realClientHello(t, "Secret.LAB")
	name, res := ClientHelloSNI(hello)
	if res != SNIFound || name != "secret.lab" {
		t.Fatalf("got %q %v (hello %d bytes)", name, res, len(hello))
	}
	// split across two segments: the first part may already carry the name
	// (Go puts server_name first) or need more; both are acceptable, but
	// the concatenation must find it
	first := hello[:200]
	n1, r1 := ClientHelloSNI(first)
	if r1 == SNINotTLS {
		t.Fatalf("first segment rejected: %q %v", n1, r1)
	}
	if n2, r2 := ClientHelloSNI(append(append([]byte{}, first...), hello[200:]...)); r2 != SNIFound || n2 != "secret.lab" {
		t.Fatalf("reassembled: %q %v", n2, r2)
	}
	for _, cut := range []int{1, 4, 5, 8, 9, 40, 60} {
		if _, r := ClientHelloSNI(hello[:cut]); r == SNINotTLS || r == SNIFound && cut < 60 {
			t.Errorf("cut at %d: %v", cut, r)
		}
	}
	if _, res := ClientHelloSNI([]byte("GET / HTTP/1.1\r\n")); res != SNINotTLS {
		t.Fatal("HTTP taken for TLS")
	}
	if _, res := ClientHelloSNI(nil); res != SNINeedMore {
		t.Fatal("empty payload")
	}
	// a ClientHello without SNI (IP target)
	noSNI := realClientHello(t, "")
	if name, res := ClientHelloSNI(noSNI); res != SNINone && res != SNIFound {
		t.Fatalf("no-SNI hello: %q %v", name, res)
	} else if res == SNIFound {
		t.Fatalf("found a name in a hello without one: %q", name)
	}
	// server_name with an illegal character
	bad := append([]byte{}, hello...)
	i := indexOf(bad, []byte("Secret.LAB"))
	if i < 0 {
		t.Fatal("name not found in raw hello")
	}
	bad[i] = 0x01
	if _, res := ClientHelloSNI(bad); res != SNINotTLS {
		t.Fatalf("invalid hostname accepted: %v", res)
	}
}

func indexOf(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		if string(b[i:i+len(sub)]) == string(sub) {
			return i
		}
	}
	return -1
}

func TestDNSQueryName(t *testing.T) {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		4, 'M', 'a', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, 0, 1}
	name, ok := DNSQueryName(q)
	if !ok || name != "mail.example.com" {
		t.Fatalf("%q %v", name, ok)
	}
	resp := append([]byte{}, q...)
	resp[2] |= 0x80
	if _, ok := DNSQueryName(resp); ok {
		t.Fatal("response parsed as query")
	}
	if _, ok := DNSQueryName(q[:len(q)-4]); ok {
		t.Fatal("truncated question accepted")
	}
	ptr := append([]byte{}, q[:12]...)
	ptr = append(ptr, 0xc0, 0x0c, 0, 1, 0, 1)
	if _, ok := DNSQueryName(ptr); ok {
		t.Fatal("compression pointer accepted")
	}
}

func TestTCPReset(t *testing.T) {
	// SYN from 10.21.0.2:40000 to 10.60.0.10:443, seq 1000
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[8], pkt[9] = 64, ProtoTCP
	copy(pkt[12:16], []byte{10, 21, 0, 2})
	copy(pkt[16:20], []byte{10, 60, 0, 10})
	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 1000)
	binary.BigEndian.PutUint32(tcp[8:12], 5000)
	tcp[12] = 5 << 4
	tcp[13] = TCPAck | 0x08 // PSH|ACK with 10 bytes payload
	pkt = append(pkt, make([]byte, 10)...)
	binary.BigEndian.PutUint16(pkt[2:4], 50)

	toSender, toReceiver := TCPReset(pkt)
	hs, ok := Parse(toSender)
	if !ok || hs.Src.String() != "10.60.0.10" || hs.Dst.String() != "10.21.0.2" || hs.SrcPort != 443 || hs.DstPort != 40000 || hs.TCPFlags != TCPRst|TCPAck {
		t.Fatalf("toSender %+v", hs)
	}
	if seq := binary.BigEndian.Uint32(toSender[24:28]); seq != 5000 {
		t.Fatalf("toSender seq %d", seq)
	}
	if ack := binary.BigEndian.Uint32(toSender[28:32]); ack != 1010 {
		t.Fatalf("toSender ack %d", ack)
	}
	hr, ok := Parse(toReceiver)
	if !ok || hr.Src.String() != "10.21.0.2" || hr.Dst.String() != "10.60.0.10" || hr.TCPFlags != TCPRst {
		t.Fatalf("toReceiver %+v", hr)
	}
	if seq := binary.BigEndian.Uint32(toReceiver[24:28]); seq != 1000 {
		t.Fatalf("toReceiver seq %d", seq)
	}
	// checksums verify to zero
	if Checksum(toSender[:20], 0) != 0 {
		t.Fatal("ip checksum")
	}
	var ph [12]byte
	copy(ph[0:4], toSender[12:16])
	copy(ph[4:8], toSender[16:20])
	ph[9] = ProtoTCP
	binary.BigEndian.PutUint16(ph[10:12], 20)
	if Checksum(toSender[20:], ^Checksum(ph[:], 0)) != 0 {
		t.Fatal("tcp checksum")
	}
	// independent verification: naive ones-complement sum over pseudo header + segment
	var naive uint32
	for _, chunk := range [][]byte{ph[:], toSender[20:]} {
		for i := 0; i+1 < len(chunk); i += 2 {
			naive += uint32(chunk[i])<<8 | uint32(chunk[i+1])
		}
	}
	for naive>>16 != 0 {
		naive = naive&0xffff + naive>>16
	}
	if uint16(naive) != 0xffff {
		t.Fatalf("tcp checksum does not verify independently: %#x", naive)
	}
	var naiveIP uint32
	for i := 0; i < 20; i += 2 {
		naiveIP += uint32(toSender[i])<<8 | uint32(toSender[i+1])
	}
	for naiveIP>>16 != 0 {
		naiveIP = naiveIP&0xffff + naiveIP>>16
	}
	if uint16(naiveIP) != 0xffff {
		t.Fatalf("ip checksum does not verify independently: %#x", naiveIP)
	}
	if a, b := TCPReset([]byte{0x45}); a != nil || b != nil {
		t.Fatal("short packet")
	}
}

func FuzzClientHelloSNI(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03})
	f.Fuzz(func(t *testing.T, b []byte) {
		name, res := ClientHelloSNI(b)
		if res == SNIFound && (name == "" || len(name) > 253) {
			t.Fatal("bad name")
		}
	})
}

func FuzzDNSQueryName(f *testing.F) {
	f.Add([]byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		name, ok := DNSQueryName(b)
		if ok && (name == "" || len(name) > 253) {
			t.Fatal("bad name")
		}
	})
}

func FuzzTCPReset(f *testing.F) {
	f.Add(make([]byte, 40))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, r := TCPReset(b)
		if (a == nil) != (r == nil) {
			t.Fatal("one of two")
		}
		if a != nil && len(a) != 40 {
			t.Fatal("size")
		}
	})
}
