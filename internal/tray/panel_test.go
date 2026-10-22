package tray

import (
	"image"
	"strings"
	"testing"
	"time"
)

// fixed-width text: 6.5 units per rune, lines of 16 units
type fakeMeasure struct{}

func (fakeMeasure) Measure(s string, f Font, width float64) (float64, float64) {
	w := float64(len([]rune(s))) * 6.5
	if width <= 0 || w <= width {
		return w, 16
	}
	lines := int(w/width) + 1
	return width, float64(lines) * 16
}

func phases() map[string]PanelInput {
	return SamplePanels(time.Date(2026, 9, 22, 14, 0, 0, 0, time.UTC))
}

func TestPanelLayout(t *testing.T) {
	for name, in := range phases() {
		p := LayoutPanel(in, fakeMeasure{}, ThemeOf(false))
		if p.W != panelW || p.H < 150 || p.H > 700 {
			t.Fatalf("%s: size %vx%v", name, p.W, p.H)
		}
		for _, it := range p.Items {
			if it.R.X < 0 || it.R.X+it.R.W > p.W+0.01 || it.R.Y < 0 || it.R.Y+it.R.H > p.H+0.01 {
				t.Fatalf("%s: %q outside the panel: %+v", name, it.Text, it.R)
			}
		}
	}
	want := map[string]string{"unconfigured": ActSetUp, "enroll": ActEnroll, "pending": ActCopyFP, "ready": ActConnect, "login": ActSignIn, "connected": ActDisconnect}
	for name, act := range want {
		p := LayoutPanel(phases()[name], fakeMeasure{}, ThemeOf(true))
		found := false
		for _, it := range p.Items {
			if it.Action == act {
				found = true
				if p.HitTest(it.R.X+it.R.W/2, it.R.Y+it.R.H/2) != act {
					t.Fatalf("%s: hit test misses %s", name, act)
				}
			}
		}
		if !found {
			t.Fatalf("%s: no %s", name, act)
		}
	}
	p := LayoutPanel(phases()["ready"], fakeMeasure{}, ThemeOf(false))
	if p.HitTest(1, 1) != "" {
		t.Fatal("the corner does something")
	}
	var profiles int
	for _, it := range p.Items {
		if strings.HasPrefix(it.Action, ActProfile) {
			profiles++
		}
	}
	if profiles != 2 {
		t.Fatalf("profile pills: %d", profiles)
	}
	// The routing profile can be changed while connected, so the pills are
	// there too - a PC that is always connected would otherwise never show
	// them. The current one is not clickable.
	cp := LayoutPanel(phases()["connected"], fakeMeasure{}, ThemeOf(false))
	profiles, clickable := 0, 0
	for _, it := range cp.Items {
		if !strings.HasPrefix(it.Action, ActProfile) {
			continue
		}
		profiles++
		if it.Pointer {
			clickable++
			if cp.HitTest(it.R.X+it.R.W/2, it.R.Y+it.R.H/2) != it.Action {
				t.Fatalf("connected: hit test misses %s", it.Action)
			}
		}
	}
	if profiles != 3 || clickable != 2 {
		t.Fatalf("connected: %d profile pills, %d of them clickable", profiles, clickable)
	}
	// busy: no actions on buttons
	in := phases()["ready"]
	in.Busy = "Connecting"
	for _, it := range LayoutPanel(in, fakeMeasure{}, ThemeOf(false)).Items {
		if it.Action == ActConnect {
			t.Fatal("connect clickable while busy")
		}
	}
}

func TestPanelPaint(t *testing.T) {
	p := LayoutPanel(phases()["connected"], fakeMeasure{}, ThemeOf(true))
	img := image.NewNRGBA(image.Rect(0, 0, int(p.W*1.5), int(p.H*1.5)))
	Paint(img, p, 1.5, ActDisconnect)
	if c := img.NRGBAAt(2, 2); c != ThemeOf(true).Bg {
		t.Fatalf("background %+v", c)
	}
}

func TestReadable(t *testing.T) {
	got := Readable(`control plane https://vpn:443: Get "https://vpn:443/api/v1/node/enroll/status": transport: pin control plane key: the key of this control plane has not been accepted yet`)
	if got != "The key of this control plane has not been accepted yet" {
		t.Fatal(got)
	}
}

// A PC in two meshes: the picker shows every network's profiles, the one in
// effect is filled and not clickable, and a profile of the other network
// asks for a switch, not for a route change.
func TestThePickerGroupsProfilesByNetwork(t *testing.T) {
	p := LayoutPanel(phases()["networks"], fakeMeasure{}, ThemeOf(false))
	var here, there, on int
	for _, it := range p.Items {
		switch {
		case it.Kind != KindBox:
		case strings.HasPrefix(it.Action, ActProfile):
			here++
			if !it.Pointer {
				on++
			}
		case strings.HasPrefix(it.Action, ActNetwork):
			there++
			if !strings.HasPrefix(it.Action, ActNetwork+"work|") {
				t.Errorf("a pill of the wrong network: %q", it.Action)
			}
			if p.HitTest(it.R.X+it.R.W/2, it.R.Y+it.R.H/2) != it.Action {
				t.Errorf("hit test misses %s", it.Action)
			}
		}
	}
	// three profiles of the network that runs, the built-ins of the other
	if here != 3 || there != 3 || on != 1 {
		t.Fatalf("%d pills here (%d in effect), %d of the other network", here, on, there)
	}
	// both names are on the panel, so a person sees which is which
	var names int
	for _, it := range p.Items {
		if it.Kind == KindText && (it.Text == "Private" || it.Text == "Work") {
			names++
		}
	}
	if names < 2 {
		t.Fatalf("the networks are not named on the panel (%d)", names)
	}
}

// With one network nothing about the picker changes: "Route" and the
// profiles, as before.
func TestASingleNetworkStillJustPicksTheRoute(t *testing.T) {
	p := LayoutPanel(phases()["connected"], fakeMeasure{}, ThemeOf(false))
	for _, it := range p.Items {
		if strings.HasPrefix(it.Action, ActNetwork) {
			t.Fatalf("a network pill with one network: %q", it.Action)
		}
		if it.Kind == KindText && it.Text == "Network" {
			t.Fatal("the picker is called Network with one network")
		}
	}
}

// A sign-in waiting in the browser must not take the panel's buttons with it:
// whoever decides against signing in has to be able to disconnect instead.
// An action of ours (Busy) does grey them out -- that is a second or two.
func TestASignInWaitingInTheBrowserLeavesTheButtonsAlive(t *testing.T) {
	act := func(in PanelInput, want string) bool {
		for _, it := range LayoutPanel(in, fakeMeasure{}, ThemeOf(false)).Items {
			if it.Action == want {
				return true
			}
		}
		return false
	}
	in := phases()["login"]
	in.Busy, in.Waiting = "", true
	if !act(in, ActDisconnect) {
		t.Error("Disconnect is dead while the browser is open")
	}
	if l := LayoutPanel(in, fakeMeasure{}, ThemeOf(false)); !strings.Contains(textOf(l), "Signing in") {
		t.Error("the panel does not say that a sign-in is under way")
	}
	in.Busy, in.Waiting = "Disconnecting", false
	if act(in, ActDisconnect) {
		t.Error("a button stayed live while an action of ours was running")
	}
}

func textOf(p Panel) string {
	var b strings.Builder
	for _, it := range p.Items {
		b.WriteString(it.Text + "\n")
	}
	return b.String()
}
