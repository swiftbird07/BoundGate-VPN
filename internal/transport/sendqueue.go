package transport

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
)

// sendQueue decouples the writer of a QUIC tunnel from its peer.
//
// quic-go's SendDatagram waits once 32 datagrams are queued on a connection
// that its congestion controller holds back, and a connection whose peer
// stopped answering (a phone that left its Wi-Fi, a NAT binding that is
// gone) holds them back until its idle timeout. The hub writes into every
// tunnel from its single TUN reader and from the serve loops of the other
// tunnels, so one such peer stopped the hub for everybody for up to a
// minute, the new tunnel of that same phone included. Each tunnel now has a
// queue of its own with its own goroutine; WritePacket never waits, and a
// full queue drops the packet as a congested path would, like the TCP
// fallback's capsuleLink.
type sendQueue struct {
	conn  *connectip.Conn
	qconn *quic.Conn
	q     chan []byte
	stop  chan struct{}
	once  sync.Once
	// fit is the largest datagram payload last known to fit (0: not asked
	// yet); larger packets ask quic-go again, smaller ones go straight on
	fit     atomic.Int64
	dropped atomic.Uint64
}

const (
	// datagramQueue is how many packets wait for one QUIC tunnel.
	datagramQueue = 256
	// datagramOverhead is what connect-ip-go and HTTP/3 put in front of an
	// IP packet in a datagram: the quarter stream ID and the context ID.
	datagramOverhead = 3
)

// oversize is a payload no QUIC packet holds: SendDatagram refuses it with
// the size that does fit, without queuing anything.
var oversize [1 << 16]byte

func newSendQueue(conn *connectip.Conn, qconn *quic.Conn) *sendQueue {
	s := &sendQueue{conn: conn, qconn: qconn, q: make(chan []byte, datagramQueue), stop: make(chan struct{})}
	go s.run()
	return s
}

func (s *sendQueue) run() {
	done := s.qconn.Context().Done()
	for {
		select {
		case b := <-s.q:
			// a datagram that no longer fits (the path got smaller since
			// write asked) is dropped: its sender is long gone
			_, _ = s.conn.WritePacket(b)
		case <-done:
			return
		case <-s.stop:
			return
		}
	}
}

// write queues b (copied) and returns at once. A packet that does not fit
// a datagram is answered with ICMP and not sent.
func (s *sendQueue) write(b []byte) (icmp []byte, err error) {
	select {
	case <-s.stop:
		return nil, net.ErrClosed
	default:
	}
	if n := len(b) + datagramOverhead; int64(n) > s.fit.Load() {
		if limit := s.limit(); n > limit {
			return tooLarge(b, limit-datagramOverhead), nil
		}
	}
	c := make([]byte, len(b))
	copy(c, b)
	select {
	case s.q <- c:
	default:
		s.dropped.Add(1)
	}
	return nil, nil
}

// limit asks quic-go for the largest datagram payload that fits now.
func (s *sendQueue) limit() int {
	var tl *quic.DatagramTooLargeError
	if err := s.qconn.SendDatagram(oversize[:]); errors.As(err, &tl) {
		s.fit.Store(tl.MaxDatagramPayloadSize)
		return int(tl.MaxDatagramPayloadSize)
	}
	return len(oversize) // closed or not negotiated: run tells
}

// close ends the queue's goroutine; later writes fail.
func (s *sendQueue) close() { s.once.Do(func() { close(s.stop) }) }
