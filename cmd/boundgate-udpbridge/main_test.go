package main

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// A datagram travels client bridge -> TCP -> server bridge -> UDP echo and
// back, for two independent sources, including a full-size QUIC packet.
func TestBridgeRoundTrip(t *testing.T) {
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(append([]byte("echo:"), buf[:n]...), src)
		}
	}()
	free := func(network string) string {
		if network == "tcp" {
			l, _ := net.Listen("tcp", "127.0.0.1:0")
			defer l.Close()
			return l.Addr().String()
		}
		l, _ := net.ListenPacket("udp", "127.0.0.1:0")
		defer l.Close()
		return l.LocalAddr().String()
	}
	tcpAddr, udpAddr := free("tcp"), free("udp")
	go runServer(tcpAddr, echo.LocalAddr().String())
	go runClient(udpAddr, tcpAddr)
	time.Sleep(100 * time.Millisecond)

	for i, payload := range [][]byte{[]byte("hello"), bytes.Repeat([]byte{0xab}, 1350)} {
		c, err := net.Dial("udp", udpAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		for try := 0; ; try++ {
			c.Write(payload)
			c.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 65535)
			n, err := c.Read(buf)
			if err == nil {
				if !bytes.Equal(buf[:n], append([]byte("echo:"), payload...)) {
					t.Fatalf("source %d: wrong echo (%d bytes)", i, n)
				}
				break
			}
			if try == 3 {
				t.Fatalf("source %d: no echo: %v", i, err)
			}
		}
	}
}
