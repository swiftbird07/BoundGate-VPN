package tray

import (
	"bytes"
	"errors"
	"fmt"
	"image/png"
	"strings"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

func TestPhases(t *testing.T) {
	approved := func(state node.State, hubs ...node.HubStatus) *node.Status {
		return &node.Status{State: state, Enrollment: "approved", Hubs: hubs}
	}
	cases := []struct {
		name string
		s    *node.Status
		err  error
		want Phase
	}{
		{"unreachable", nil, errors.New("node daemon not reachable"), ServiceDown},
		{"unconfigured", &node.Status{State: "unconfigured"}, nil, Unconfigured},
		{"unknown", &node.Status{State: node.StateDown, Enrollment: "unknown"}, nil, NeedsEnroll},
		{"confirmed", &node.Status{State: node.StateDown, Enrollment: "confirmed"}, nil, Pending},
		{"revoked", &node.Status{State: node.StateDown, Enrollment: "revoked"}, nil, Revoked},
		{"down", approved(node.StateDown), nil, Ready},
		{"starting", approved(node.StateStarting), nil, Connecting},
		{"up, hub connecting", approved(node.StateUp, node.HubStatus{State: "connecting"}), nil, Connecting},
		{"up, login", &node.Status{State: node.StateUp, Enrollment: "approved", LoginRequired: true}, nil, LoginRequired},
		{"up", approved(node.StateUp, node.HubStatus{State: "connecting"}, node.HubStatus{State: "connected"}), nil, Connected},
	}
	for _, c := range cases {
		if got := PhaseOf(c.s, c.err); got != c.want {
			t.Errorf("%s: phase %d, want %d", c.name, got, c.want)
		}
	}
}

func TestDescribe(t *testing.T) {
	v := Describe(&node.Status{State: node.StateUp, Enrollment: "approved", OverlayIP: "10.21.0.7",
		User: &node.UserStatus{Subject: "u1", Username: "martin"}, Hubs: []node.HubStatus{{State: "connected"}}}, nil)
	if v.Color != Green || !v.CanDown || v.CanUp || !v.CanLogout || v.CanLogin || v.Title != "Connected as 10.21.0.7" || v.Detail != "Signed in as martin" {
		t.Fatalf("connected: %+v", v)
	}
	v = Describe(&node.Status{State: node.StateDown, Enrollment: "approved"}, nil)
	if !v.CanUp || v.CanDown || v.Color != Gray {
		t.Fatalf("ready: %+v", v)
	}
	v = Describe(nil, errors.New("node daemon not reachable at x: refused"))
	if v.Color != Red || !strings.Contains(v.Detail, "boundgate-node start") {
		t.Fatalf("down: %+v", v)
	}
	v = Describe(nil, fmt.Errorf("node daemon not reachable at x: %w", ErrNoAccess))
	if v.Color != Red || !strings.Contains(v.Detail, "Sign out") || v.CanSetup {
		t.Fatalf("no access: %+v", v)
	}
	v = Describe(&node.Status{State: "unconfigured"}, nil)
	if !v.CanSetup || v.CanEnroll || v.Color != Amber {
		t.Fatalf("unconfigured: %+v", v)
	}
	long := View{Title: strings.Repeat("ä", 200)}
	if n := len([]rune(long.Tooltip())); n != 127 {
		t.Fatalf("tooltip %d runes", n)
	}
}

func TestRate(t *testing.T) {
	t0 := time.Unix(1000, 0)
	s := &node.Status{Hubs: []node.HubStatus{{TunnelStats: transport.TunnelStats{BytesIn: 1000, BytesOut: 10}}, {TunnelStats: transport.TunnelStats{BytesIn: 1000}}}}
	a := ReadingOf(s, t0)
	s.Hubs[0].BytesIn += 4000
	b := ReadingOf(s, t0.Add(2*time.Second))
	if r := RateOf(a, b); !r.Valid || r.In != 2000 || r.Out != 0 {
		t.Fatalf("rate %+v", r)
	}
	if r := RateOf(b, a); r.Valid {
		t.Fatal("rate over a counter reset")
	}
	if r := RateOf(Reading{}, b); r.Valid {
		t.Fatal("rate without a first reading")
	}
	if Bytes(1536) != "1.5 KiB" || Bytes(12) != "12 B" || Bytes(3<<30) != "3.0 GiB" {
		t.Fatal(Bytes(1536), Bytes(12), Bytes(3<<30))
	}
}

func TestIcon(t *testing.T) {
	for c := Gray; c <= Red; c++ {
		b := Icon(c)
		if b[2] != 1 || b[4] != 1 || b[6] != 32 {
			t.Fatalf("ico header % x", b[:8])
		}
		img, err := png.Decode(bytes.NewReader(b[22:]))
		if err != nil || img.Bounds().Dx() != 32 {
			t.Fatalf("png: %v", err)
		}
		if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
			t.Fatal("corner not transparent")
		}
		if r, g, bb, _ := img.At(16, 9).RGBA(); r>>8 < 0xf0 || g>>8 < 0xf0 || bb>>8 < 0xf0 {
			t.Fatalf("arch top not white: %d %d %d", r>>8, g>>8, bb>>8)
		}
	}
}
