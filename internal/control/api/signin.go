package api

import (
	"net/netip"
	"sync"
	"time"
)

// SignInHint tells a device that a node refused one of its connections and
// that a user session would have permitted it (acl.Decision.
// SignInWouldPermit). It travels in the answer to the device's heartbeat,
// once. It grants nothing: the policies decide again after the sign-in.
type SignInHint struct {
	// Dst and Port are where the device wanted to go, Proto "tcp", "udp", …
	Dst   string `json:"dst"`
	Port  int    `json:"port,omitempty"`
	Proto string `json:"proto,omitempty"`
	// Name is what the connection was for, when the deciding node saw it:
	// the TLS server name, the DNS question or a name the device resolved.
	Name string `json:"name,omitempty"`
	// Via is the node that decided (a hub, a subnet router, a peer).
	Via string    `json:"via,omitempty"`
	At  time.Time `json:"at"`
}

// HeartbeatReply is the body of a heartbeat's answer; without anything to
// say the control plane answers 204.
type HeartbeatReply struct {
	SignIn *SignInHint `json:"sign_in,omitempty"`
}

// signInTTL is how long a hint waits for its device's next heartbeat.
const signInTTL = 10 * time.Minute

// signInHints keeps the newest hint per device until its heartbeat takes
// it. In memory: a restart loses at most a suggestion. One entry per node
// at most, so the map is as large as the fleet.
//
// The word of the deciding node is all there is to it: any approved node
// could report a hint for any other (R137). What that buys an attacker is
// a "Sign in" notice on a device, whose button starts that device's own
// sign-in at its own control plane — nothing that goes anywhere else.
type signInHints struct {
	mu sync.Mutex
	m  map[string]SignInHint
}

func (s *signInHints) note(node string, h SignInHint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]SignInHint{}
	}
	if old, ok := s.m[node]; ok && old.At.After(h.At) {
		return
	}
	s.m[node] = h
}

// take hands the device its hint, once, if it is fresh.
func (s *signInHints) take(node string, now time.Time) (SignInHint, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.m[node]
	if !ok {
		return h, false
	}
	delete(s.m, node)
	return h, now.Sub(h.At) < signInTTL
}

// hintFrom reads a shipped deny record. ok: the record asks to tell its
// principal, who is a node the control plane knows.
func hintFrom(ev ShippedEvent, via string) (string, SignInHint, bool) {
	if ev.Stream != ShipStreamFlow || ev.Message != "deny" {
		return "", SignInHint{}, false
	}
	if b, _ := ev.Attrs["sign_in"].(bool); !b {
		return "", SignInHint{}, false
	}
	principal, _ := ev.Attrs["principal"].(string)
	if principal == "" || ev.Attrs["principal_name"] == nil {
		return "", SignInHint{}, false // principal_name is set only for a known node
	}
	// The hint is shown on the device as a notification with a button. Its
	// words are the reporting node's, and any approved node may report
	// one for any other (R137): so they are an address, a port, a protocol
	// and a host name, and nothing else gets through to the screen.
	h := SignInHint{Via: via, At: ev.TS}
	dst, _ := ev.Attrs["dst"].(string)
	if a, err := netip.ParseAddr(dst); err != nil {
		return "", SignInHint{}, false
	} else {
		h.Dst = a.String()
	}
	switch p, _ := ev.Attrs["proto"].(string); p {
	case "", "tcp", "udp", "icmp", "icmpv6":
		h.Proto = p
	default:
		return "", SignInHint{}, false
	}
	switch p := ev.Attrs["dport"].(type) {
	case float64:
		h.Port = int(p)
	case int:
		h.Port = p
	case uint16:
		h.Port = int(p)
	}
	if h.Port < 0 || h.Port > 65535 {
		return "", SignInHint{}, false
	}
	for _, k := range []string{"sni", "dns_name"} {
		if v, _ := ev.Attrs[k].(string); v != "" {
			h.Name = v
			break
		}
	}
	if h.Name == "" {
		if ns, _ := ev.Attrs["resolved_names"].([]any); len(ns) > 0 {
			h.Name, _ = ns[0].(string)
		}
	}
	if h.Name != "" && !hostNameForDisplay(h.Name) {
		h.Name = "" // the address alone, then
	}
	return principal, h, true
}

// hostNameForDisplay: a host name as a device may show it -- letters,
// digits, dots, dashes and underscores, at most 253 of them -- and not a
// sentence somebody wrote for the screen.
func hostNameForDisplay(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	return true
}
