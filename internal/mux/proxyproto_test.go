package mux

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// A trusted front may speak PROXY v2 (mux, HAProxy, Traefik), v1 (nginx
// stream) or send no header (an HTTP proxy re-encrypting to the admin
// name); an untrusted peer is never parsed.
func TestProxyListenerHeaders(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pl := &ProxyListener{Listener: ln, Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}

	type got struct{ remote, payload string }
	res := make(chan got, 1)
	go func() {
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				remote := c.RemoteAddr().String()
				b, _ := io.ReadAll(c)
				res <- got{remote, string(b)}
			}()
		}
	}()

	tls := "\x16\x03\x01 hello" // what a TLS record starts with
	v2 := ProxyV2Header(&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 40000}, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443})
	cases := []struct{ name, send, remote, payload string }{
		{"v2", string(v2) + tls, "203.0.113.7:40000", tls},
		{"v1 tcp4", "PROXY TCP4 198.51.100.9 192.0.2.1 51234 443\r\n" + tls, "198.51.100.9:51234", tls},
		{"v1 tcp6", "PROXY TCP6 2001:db8::9 2001:db8::1 51234 443\r\n" + tls, "[2001:db8::9]:51234", tls},
		{"v1 unknown", "PROXY UNKNOWN\r\n" + tls, "127.0.0.1", tls},
		{"no header", tls, "127.0.0.1", tls},
	}
	for _, tc := range cases {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte(tc.send))
		_ = c.(*net.TCPConn).CloseWrite()
		g := <-res
		c.Close()
		host, _, _ := net.SplitHostPort(g.remote)
		if g.payload != tc.payload || (g.remote != tc.remote && host != tc.remote) {
			t.Errorf("%s: remote %q payload %q", tc.name, g.remote, g.payload)
		}
	}

	// malformed v1 from a trusted front: the connection yields an error, not data
	c, _ := net.Dial("tcp", ln.Addr().String())
	_, _ = c.Write([]byte("PROXY TCP4 not-an-ip 192.0.2.1 1 443\r\n" + tls))
	_ = c.(*net.TCPConn).CloseWrite()
	if g := <-res; g.payload != "" {
		t.Errorf("malformed v1 delivered %q", g.payload)
	}
	c.Close()
}

// The header is read inside the first Read: the deadline its user set for
// that Read (the front's wait for a ClientHello) still holds afterwards, so
// a client that sends the header and then nothing is dropped in time.
func TestProxyHeaderKeepsTheReadDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pl := &ProxyListener{Listener: ln, Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(ProxyV2Header(&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 40000}, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}))
	sc, err := pl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	_ = sc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	done := make(chan error, 1)
	go func() {
		_, err := sc.Read(make([]byte, 16))
		done <- err
	}()
	select {
	case err := <-done:
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("read after the header: %v, want a timeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the read deadline was lost when the header was read")
	}
}
