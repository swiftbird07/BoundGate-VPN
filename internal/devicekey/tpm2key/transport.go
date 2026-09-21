package tpm2key

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
)

// openTPM connects to a TPM. device is a character device path
// (/dev/tpmrm0), or "unix:PATH" / "tcp:HOST:PORT" for a software TPM that
// speaks raw TPM commands on a stream socket (swtpm). raw reports the
// latter: no resource manager sits in between.
func openTPM(device string) (t transport.TPMCloser, raw bool, err error) {
	if device == "" {
		device = DefaultDevice
	}
	for _, network := range []string{"unix", "tcp"} {
		if addr, ok := strings.CutPrefix(device, network+":"); ok {
			s := &stream{network: network, addr: addr}
			if err := s.dial(); err != nil {
				return nil, false, fmt.Errorf("tpm2key: %w", err)
			}
			return s, true, nil
		}
	}
	t, err = openDevice(device)
	if err != nil {
		return nil, false, fmt.Errorf("tpm2key: open %s: %w", device, err)
	}
	return t, false, nil
}

// stream carries TPM commands over a stream socket. A response is framed by
// the size field of its header (tag u16, size u32, code u32).
type stream struct {
	network, addr string
	mu            sync.Mutex
	conn          net.Conn
}

const (
	tpmHeaderSize  = 10
	tpmMaxResponse = 1 << 16
	tpmTimeout     = 30 * time.Second
)

func (s *stream) dial() error {
	c, err := net.DialTimeout(s.network, s.addr, 5*time.Second)
	if err != nil {
		return err
	}
	s.conn = c
	return nil
}

// Send implements transport.TPM. A broken connection is dialed again once:
// the TPM keeps its state, only the socket is new.
func (s *stream) Send(cmd []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rsp, err := s.roundTrip(cmd)
	if err == nil {
		return rsp, nil
	}
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	if derr := s.dial(); derr != nil {
		return nil, fmt.Errorf("tpm2key: %w (redial: %v)", err, derr)
	}
	return s.roundTrip(cmd)
}

func (s *stream) roundTrip(cmd []byte) ([]byte, error) {
	if s.conn == nil {
		return nil, errors.New("not connected")
	}
	_ = s.conn.SetDeadline(time.Now().Add(tpmTimeout))
	if _, err := s.conn.Write(cmd); err != nil {
		return nil, err
	}
	hdr := make([]byte, tpmHeaderSize)
	if _, err := io.ReadFull(s.conn, hdr); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(hdr[2:6])
	if size < tpmHeaderSize || size > tpmMaxResponse {
		return nil, fmt.Errorf("implausible response size %d", size)
	}
	rsp := make([]byte, size)
	copy(rsp, hdr)
	if _, err := io.ReadFull(s.conn, rsp[tpmHeaderSize:]); err != nil {
		return nil, err
	}
	return rsp, nil
}

// Close implements io.Closer.
func (s *stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}
