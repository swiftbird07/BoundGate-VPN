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
