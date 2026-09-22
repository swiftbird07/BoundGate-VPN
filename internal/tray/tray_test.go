package tray

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
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
	decode := func(b []byte) image.Image {
		t.Helper()
		if b[2] != 1 || b[4] != 1 {
			t.Fatalf("ico header % x", b[:8])
		}
		img, err := png.Decode(bytes.NewReader(b[22:]))
		if err != nil {
			t.Fatalf("png: %v", err)
		}
		return img
	}
	for c := Gray; c <= Red; c++ {
		for _, light := range []bool{false, true} {
			for _, n := range []int{32, 48, 64} {
				img := decode(Icon(c, light, n, n/2))
				if img.Bounds().Dx() != n || b0(img) {
					t.Fatalf("%d px: size %d or corner not transparent", n, img.Bounds().Dx())
				}
			}
		}
	}
	// 32 px: frame A's top edge sits at y = 4 units = 6.4 px, x = 7 units
	at := func(c Color, light bool, x, y int) color.NRGBA {
		return color.NRGBAModel.Convert(decode(Icon(c, light, 32, 16)).At(x, y)).(color.NRGBA)
	}
	if p := at(Green, false, 11, 6); p.A < 0xc0 || p.R < 0xf0 {
		t.Fatalf("dark taskbar: frame not white: %+v", p)
	}
	if p := at(Green, true, 11, 6); p.A < 0xc0 || p.R > 0x40 {
		t.Fatalf("light taskbar: frame not dark: %+v", p)
	}
	if p := at(Amber, true, 26, 7); p.R < 0xf0 || p.G < 0xc0 || p.B > 0x20 {
		t.Fatalf("attention dot not yellow: %+v", p)
	}
	if p := at(Green, true, 26, 7); p.A != 0 {
		t.Fatalf("connected has no dot: %+v", p)
	}
}

// b0: the bottom left corner is not transparent
func b0(img image.Image) bool {
	_, _, _, a := img.At(0, img.Bounds().Dy()-1).RGBA()
	return a != 0
}
