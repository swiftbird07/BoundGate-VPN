// Package tray is the Windows tray app's view of the node, apart from the
// tray itself: which phase the node is in, what the menu says, and the icon.
// It follows the Mac app's phases (apps/macos, AppModel.phase), so both
// clients say the same thing about the same state.
package tray

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
)

// ErrNoAccess is what the tray reports when the service answers but its
// socket refuses this account (the group comes with the next sign-in).
var ErrNoAccess = errors.New("no access to the BoundGate service")

// Phase is where the node stands, from the user's point of view.
type Phase int

const (
	ServiceDown  Phase = iota // the daemon does not answer
	Unconfigured              // no control plane yet
	NeedsEnroll
	Pending // enrolled, waiting for the administrator
	Revoked
	Ready // approved, tunnel down
	Connecting
	LoginRequired // tunnel up, the hubs want a user session
	Connected
)

// PhaseOf derives the phase from a status; err is the error of fetching it.
func PhaseOf(s *node.Status, err error) Phase {
	if err != nil || s == nil {
		return ServiceDown
	}
	if s.State == "unconfigured" {
		return Unconfigured
	}
	switch s.Enrollment {
	case "approved":
	case "pending", "confirmed":
		return Pending
	case "revoked":
		return Revoked
	default:
		return NeedsEnroll
	}
	switch s.State {
	case node.StateStarting:
		return Connecting
	case node.StateUp:
		for _, h := range s.Hubs {
			if h.State == "connected" {
				return Connected
			}
		}
		if s.LoginRequired {
			return LoginRequired
		}
		return Connecting
	}
	return Ready
}

// Color is the icon's state.
type Color int

const (
	Gray  Color = iota // down, nothing to do
	Amber              // needs the user or is on its way
	Green              // connected
	Red                // broken
)

// View is everything the tray shows for one status.
type View struct {
	Phase   Phase
	Color   Color
	Title   string // first menu line, and the tooltip
	Detail  string // second line: what to do, or the error
	CanUp   bool
	CanDown bool
	// CanLogin: the hubs want a session, or one could be refreshed.
	CanLogin  bool
	CanLogout bool
	CanEnroll bool
	CanSetup  bool // no control plane yet: ask for its address
}

// Describe builds the view; err is the error of the last try to reach the
// daemon.
func Describe(s *node.Status, err error) View {
	p := PhaseOf(s, err)
	v := View{Phase: p}
	switch p {
	case ServiceDown:
		v.Color, v.Title = Red, "BoundGate service not running"
		v.Detail = "Start it as administrator: boundgate-node start"
		if errors.Is(err, ErrNoAccess) {
			v.Title = "No access to the BoundGate service"
			v.Detail = "Sign out of Windows and in again (group BoundGate Users)"
		} else if err != nil && !strings.Contains(err.Error(), "not reachable") {
			v.Detail = err.Error()
		}
	case Unconfigured:
		v.Color, v.Title, v.CanSetup = Amber, "Not set up", true
		v.Detail = "Set up: enter your organization's control plane"
	case NeedsEnroll:
		v.Color, v.Title, v.CanEnroll = Amber, "Not enrolled", true
		v.Detail = "Request access from " + s.Control
		if s.EnrollmentError != "" {
			v.Detail = s.EnrollmentError
		}
	case Pending:
		v.Color, v.Title = Amber, "Waiting for approval"
		v.Detail = "Give your administrator the fingerprint " + ShortFingerprint(s.Fingerprint)
	case Revoked:
		v.Color, v.Title = Red, "Access revoked"
		v.Detail = "Ask your administrator"
	case Ready:
		v.Color, v.Title, v.CanUp = Gray, "Disconnected", true
		v.Detail = s.LastError
	case Connecting:
		v.Color, v.Title, v.CanDown = Amber, "Connecting…", true
		v.Detail = firstNonEmpty(hubError(s), s.ControlError)
	case LoginRequired:
		v.Color, v.Title, v.CanDown, v.CanLogin = Amber, "Sign in required", true, true
		v.Detail = "Your network wants you to sign in"
	case Connected:
		v.Color, v.Title, v.CanDown = Green, "Connected", true
		if s.OverlayIP != "" {
			v.Title += " as " + s.OverlayIP
		}
		if s.User != nil {
			v.Detail = "Signed in as " + firstNonEmpty(s.User.Username, s.User.Email, s.User.Subject)
		}
	}
	if s != nil && s.User != nil && p >= Ready {
		v.CanLogout = true
	}
	if p == Connected && s.User == nil {
		v.CanLogin = true
	}
	return v
}

// Tooltip is the text on hover; Windows cuts it at 127 characters.
func (v View) Tooltip() string {
	t := []rune("BoundGate: " + v.Title)
	if len(t) > 127 {
		t = append(t[:126], '…')
	}
	return string(t)
}

func hubError(s *node.Status) string {
	for _, h := range s.Hubs {
		if h.Error != "" {
			return h.Name + ": " + h.Error
		}
	}
	return ""
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// ShortFingerprint keeps what a person compares: the first and last groups.
func ShortFingerprint(fp string) string {
	if len(fp) <= 24 {
		return fp
	}
	return fp[:11] + "…" + fp[len(fp)-8:]
}

// Details are the lines of the Details submenu, hidden until opened like the
// Mac app's Details section.
func Details(s *node.Status, r Rate) []string {
	if s == nil {
		return nil
	}
	var out []string
	add := func(k, v string) {
		if v != "" {
			out = append(out, k+": "+v)
		}
	}
	add("Node", s.NodeName)
	add("Address", s.OverlayIP)
	add("Profile", s.Profile)
	for _, h := range s.Hubs {
		line := h.State
		if h.State == "connected" {
			line = fmt.Sprintf("%s (%s), ↓ %s ↑ %s", h.State, tunnelProtocol(h.Transport), Bytes(h.BytesIn), Bytes(h.BytesOut))
		}
		add("Hub "+h.Name, line)
	}
	if r.Valid {
		add("Now", fmt.Sprintf("↓ %s/s ↑ %s/s", Bytes(uint64(r.In)), Bytes(uint64(r.Out))))
	}
	add("Control plane", s.Control)
	add("Control channel", controlProtocol(s.ControlTransport))
	if s.Interface != "" {
		add("Adapter", fmt.Sprintf("%s, MTU %d", s.Interface, s.MTU))
	}
	key := s.KeyKind
	if s.HardwareBound {
		key += ", hardware-bound"
	}
	add("Device key", key)
	add("Fingerprint", s.Fingerprint)
	add("Version", s.Version)
	return out
}

func tunnelProtocol(t string) string {
	switch t {
	case "quic":
		return "QUIC, UDP/443"
	case "tcp":
		return "TCP/443 fallback"
	}
	return t
}

func controlProtocol(t string) string {
	switch t {
	case "h3":
		return "HTTP/3"
	case "h2":
		return "HTTP/2 over TCP"
	}
	return t
}

// Bytes formats a byte count with binary units.
func Bytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// Reading is the traffic total at one poll.
type Reading struct {
	In, Out uint64
	At      time.Time
}

// ReadingOf sums the hub tunnels.
func ReadingOf(s *node.Status, at time.Time) Reading {
	r := Reading{At: at}
	if s == nil {
		return r
	}
	for _, h := range s.Hubs {
		r.In += h.BytesIn
		r.Out += h.BytesOut
	}
	return r
}

// Rate is bytes per second between two readings.
type Rate struct {
	In, Out float64
	Valid   bool
}

// RateOf is the rate from prev to now; a counter that went back (a new
// tunnel) gives no rate rather than a wrong one.
func RateOf(prev, now Reading) Rate {
	dt := now.At.Sub(prev.At).Seconds()
	if prev.At.IsZero() || dt <= 0 || now.In < prev.In || now.Out < prev.Out {
		return Rate{}
	}
	return Rate{In: float64(now.In-prev.In) / dt, Out: float64(now.Out-prev.Out) / dt, Valid: true}
}
