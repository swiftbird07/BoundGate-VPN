package transport

import (
	"errors"

	"github.com/quic-go/quic-go"
)

// QUIC application error codes used when the gateway closes a tunnel. The
// agent uses them to decide whether to reconnect.
const (
	// ErrCodeRevoked: the device was unenrolled. Do not reconnect.
	ErrCodeRevoked quic.ApplicationErrorCode = 0x42420001
	// ErrCodeSessionExpired: the user session ended. Re-login, then reconnect.
	ErrCodeSessionExpired quic.ApplicationErrorCode = 0x42420002
	// ErrCodeShutdown: the gateway is going down. Reconnect with backoff.
	ErrCodeShutdown quic.ApplicationErrorCode = 0x42420003
	// ErrCodePolicy: the gateway rejected the tunnel for policy reasons.
	ErrCodePolicy quic.ApplicationErrorCode = 0x42420004
)

// CloseCode extracts the application error code from a connection error, if
// the peer closed the connection with one: QUIC's application error, or the
// close capsule of the TCP fallback.
func CloseCode(err error) (quic.ApplicationErrorCode, bool) {
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return appErr.ErrorCode, true
	}
	var ce *CloseError
	if errors.As(err, &ce) && ce.Remote {
		return ce.Code, true
	}
	return 0, false
}
