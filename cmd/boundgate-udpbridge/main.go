// boundgate-udpbridge carries UDP datagrams over TCP. Lab only.
//
// The compose lab runs in a Colima VM whose default port forwarder (ssh)
// forwards TCP only, so a node on the Mac host (M5) cannot reach the hubs'
// UDP/443 tunnel listeners. One bridge on the Mac (-client) accepts the
// node's datagrams and sends them, length-prefixed, over a forwarded TCP
// port to a bridge inside the lab (-server), which emits them as UDP to the
// hub. QUIC runs end to end through it; the bridge sees only ciphertext and
// is not part of the product. With a UDP-capable forwarder (Colima
// `portForwarder: grpc`) it is not needed.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const idle = 3 * time.Minute

func main() {
	client := flag.String("client", "", "comma-separated udpListen=tcpTarget pairs (Mac side)")
	server := flag.String("server", "", "comma-separated tcpListen=udpTarget pairs (lab side)")
	probe := flag.String("probe", "", "send a QUIC version-negotiation probe to host:port and report whether a QUIC server answers")
	flag.Parse()
	if *probe != "" {
		if err := runProbe(*probe); err != nil {
			fmt.Fprintln(os.Stderr, "probe:", err)
			os.Exit(1)
		}
		return
	}
	if (*client == "") == (*server == "") {
		fmt.Fprintln(os.Stderr, "usage: boundgate-udpbridge -client 127.0.0.1:15431=127.0.0.1:24431[,...] | -server :24431=hub1:443[,...]")
		os.Exit(2)
	}
	var wg sync.WaitGroup
	for _, m := range strings.Split(*client+*server, ",") {
		from, to, ok := strings.Cut(strings.TrimSpace(m), "=")
		if !ok {
			log.Fatalf("bad mapping %q", m)
		}
		wg.Add(1)
		if *client != "" {
			go func() { defer wg.Done(); log.Fatal(runClient(from, to)) }()
		} else {
			go func() { defer wg.Done(); log.Fatal(runServer(from, to)) }()
		}
	}
	wg.Wait()
}

func writeFrame(w io.Writer, p []byte) error {
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf, uint16(len(p)))
	copy(buf[2:], p)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader, buf []byte) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// runClient: one TCP connection per UDP source, so the lab side uses one UDP
// socket per node-side socket and the hub sees distinct peers.
func runClient(udpListen, tcpTarget string) error {
	pc, err := net.ListenPacket("udp", udpListen)
	if err != nil {
		return err
	}
	log.Printf("udp %s -> tcp %s", udpListen, tcpTarget)
	var mu sync.Mutex
	conns := map[string]net.Conn{}
	buf := make([]byte, 65535)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		key := src.String()
		mu.Lock()
		c := conns[key]
		mu.Unlock()
		if c == nil {
			c, err = net.DialTimeout("tcp", tcpTarget, 5*time.Second)
			if err != nil {
				log.Printf("dial %s: %v", tcpTarget, err)
				continue
			}
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetNoDelay(true)
			}
			mu.Lock()
			conns[key] = c
			mu.Unlock()
			go func(c net.Conn, src net.Addr) {
				defer func() { c.Close(); mu.Lock(); delete(conns, key); mu.Unlock() }()
				rb := make([]byte, 65535)
				for {
					c.SetReadDeadline(time.Now().Add(idle))
					p, err := readFrame(c, rb)
					if err != nil {
						return
					}
					pc.WriteTo(p, src)
				}
			}(c, src)
		}
		if err := writeFrame(c, buf[:n]); err != nil {
			c.Close()
		}
	}
}

func runServer(tcpListen, udpTarget string) error {
	ln, err := net.Listen("tcp", tcpListen)
	if err != nil {
		return err
	}
	log.Printf("tcp %s -> udp %s", tcpListen, udpTarget)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetNoDelay(true)
			}
			u, err := net.Dial("udp", udpTarget)
			if err != nil {
				log.Printf("udp %s: %v", udpTarget, err)
				return
			}
			defer u.Close()
			go func() {
				defer c.Close()
				rb := make([]byte, 65535)
				for {
					u.SetReadDeadline(time.Now().Add(idle))
					n, err := u.Read(rb)
					if err != nil {
						return
					}
					if writeFrame(c, rb[:n]) != nil {
						return
					}
				}
			}()
			buf := make([]byte, 65535)
			for {
				c.SetReadDeadline(time.Now().Add(idle))
				p, err := readFrame(c, buf)
				if err != nil {
					return
				}
				u.Write(p)
			}
		}(c)
	}
}

// runProbe sends an Initial-sized long-header packet with a reserved version;
// every QUIC server answers it with a Version Negotiation packet (RFC 9000
// section 6) that echoes the connection ids. No handshake, no state.
func runProbe(addr string) error {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	pkt := make([]byte, 1200)
	copy(pkt, []byte{0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8, 1, 2, 3, 4, 5, 6, 7, 8, 8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18})
	buf := make([]byte, 1500)
	for try := 1; try <= 3; try++ {
		start := time.Now()
		if _, err := c.Write(pkt); err != nil {
			return err
		}
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			continue
		}
		if n >= 7 && buf[0]&0x80 != 0 && binary.BigEndian.Uint32(buf[1:5]) == 0 {
			fmt.Printf("%s: QUIC server answered (version negotiation, %d bytes, %s)\n", addr, n, time.Since(start).Round(time.Millisecond))
			return nil
		}
		return fmt.Errorf("%s: unexpected %d-byte answer", addr, n)
	}
	return fmt.Errorf("%s: no answer over UDP", addr)
}
