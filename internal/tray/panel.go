package tray

import (
	"errors"
	"fmt"
	"image"
	"image/color"
	"math"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// The panel is what a click on the tray icon opens: the Windows counterpart
// of the Mac app's window (apps/macos, PanelView), with the same parts: a
// header with the mark and a state pill, one card for the phase, the action
// that matters, and a footer. This file lays it out and paints its shapes in
// 96-dpi units; the platform draws the text and the window
// (cmd/boundgate-tray/panel_windows.go), measuring text through Measurer.

// Theme holds the tokens of docs/DESIGN.md (web/src/app.css), as the Mac's
// Theme.swift does.
type Theme struct {
	Bg, Panel, Panel2, Panel3, Border, BorderStrong color.NRGBA
	Text, Text2, Text3                              color.NRGBA
	Ok, Warn, Bad, Info                             color.NRGBA
	LogoGround, LogoMark                            color.NRGBA
}

var (
	Accent   = color.NRGBA{0xff, 0xcc, 0x00, 0xff}
	AccentHi = color.NRGBA{0xff, 0xd8, 0x3d, 0xff}
	OnAccent = color.NRGBA{0x2a, 0x2a, 0x2a, 0xff}
	charcoal = color.NRGBA{0x2a, 0x2a, 0x2a, 0xff}
)

func rgb(v uint32) color.NRGBA {
	return color.NRGBA{uint8(v >> 16), uint8(v >> 8), uint8(v), 0xff}
}

func alpha(c color.NRGBA, a float64) color.NRGBA {
	c.A = uint8(float64(c.A)*a + 0.5)
	return c
}

// ThemeOf gives the dark or the light theme.
func ThemeOf(dark bool) Theme {
	if dark {
		return Theme{
			Bg: rgb(0x1d1d1d), Panel: rgb(0x2a2a2a), Panel2: rgb(0x343434), Panel3: rgb(0x3e3e3e),
			Border: alpha(rgb(0xffffff), 0.08), BorderStrong: alpha(rgb(0xffffff), 0.17),
			Text: rgb(0xf5f2ea), Text2: rgb(0xb9b4a8), Text3: rgb(0x868074),
			Ok: rgb(0x5fd38d), Warn: rgb(0xff9f45), Bad: rgb(0xff6b6b), Info: rgb(0x7db8ff),
			LogoGround: Accent, LogoMark: charcoal,
		}
	}
	return Theme{
		Bg: rgb(0xf4f2eb), Panel: rgb(0xffffff), Panel2: rgb(0xf0ede4), Panel3: rgb(0xe6e2d6),
		Border: alpha(charcoal, 0.10), BorderStrong: alpha(charcoal, 0.24),
		Text: rgb(0x2a2a2a), Text2: rgb(0x5d594f), Text3: rgb(0x8b8678),
		Ok: rgb(0x178a4a), Warn: rgb(0xc2560a), Bad: rgb(0xcf3030), Info: rgb(0x1f62c4),
		LogoGround: charcoal, LogoMark: Accent,
	}
}

// Font is a text style; the platform maps it to a face, size and weight.
type Font int

const (
	FontBody     Font = iota // 12, regular
	FontStrong               // 12, semibold
	FontSmall                // 11.5, regular
	FontPill                 // 11.5, semibold
	FontTitle                // 15, bold: a card's heading
	FontBig                  // 22, bold: the overlay address
	FontWordmark             // 17, bold
	FontButton               // 13, semibold
	FontButtonLg             // 14, semibold
	FontMono                 // 12, monospaced
)

// Measurer measures text in 96-dpi units; width 0 means one line.
type Measurer interface {
	Measure(text string, f Font, width float64) (w, h float64)
}

// Rect is in 96-dpi units.
type Rect struct{ X, Y, W, H float64 }

// Contains reports whether the point lies inside.
func (r Rect) Contains(x, y float64) bool {
	return x >= r.X && x < r.X+r.W && y >= r.Y && y < r.Y+r.H
}

// Align of a text in its rectangle.
type Align int

const (
	Left Align = iota
	Center
	Right
)

// Item is one thing on the panel: a box (fill, border, radius), a text, the
// logo tile or a dot. Action names what a click on it does ("" = nothing).
type Item struct {
	Kind          ItemKind
	R             Rect
	Fill, Stroke  color.NRGBA
	Radius        float64
	Text          string
	Font          Font
	Color         color.NRGBA
	Align         Align
	Wrap          bool // the text breaks into lines; otherwise one line, cut with an ellipsis
	Action        string
	HoverFill     color.NRGBA // a box's fill under the mouse
	Pointer       bool        // a hand cursor over it
	Mono          bool
	VerticalAlign bool // center one line vertically in R
}

// ItemKind of an Item.
type ItemKind int

const (
	KindBox ItemKind = iota
	KindText
	KindTile
	KindDot
	KindChevron // Text "down" or "right"
)

// Panel is the laid-out panel.
type Panel struct {
	W, H  float64
	Bg    color.NRGBA
	Items []Item
}

// HitTest returns the action under a point.
func (p Panel) HitTest(x, y float64) string {
	for i := len(p.Items) - 1; i >= 0; i-- {
		if it := p.Items[i]; it.Action != "" && it.R.Contains(x, y) {
			return it.Action
		}
	}
	return ""
}

// Actions of the panel.
const (
	ActConnect    = "connect"
	ActDisconnect = "disconnect"
	ActSignIn     = "signin"
	ActSignOut    = "signout"
	ActSetUp      = "setup"
	ActEnroll     = "enroll"
	ActCopyFP     = "copyfp"
	ActDetails    = "details"
	ActQuit       = "quit"
	ActProfile    = "profile:" // + the profile's name
)

// PanelInput is everything the panel shows.
type PanelInput struct {
	Status      *node.Status
	Err         error // of fetching the status
	Busy        string
	Profiles    []string
	Rate        Rate
	ActionError string // the last action's failure
	DetailsOpen bool
	Hover       string // the action under the mouse
	Now         time.Time
}

const (
	panelW  = 340.0
	pad     = 14.0
	gap     = 12.0
	cardPad = 14.0
	radius  = 14.0
	radSm   = 10.0
)

type layout struct {
	t     Theme
	m     Measurer
	in    PanelInput
	items []Item
	y     float64
}

func (l *layout) add(it Item) { l.items = append(l.items, it) }

// text adds a wrapped text of width w at x and returns its height.
func (l *layout) text(x, w float64, s string, f Font, c color.NRGBA) float64 {
	_, h := l.m.Measure(s, f, w)
	l.add(Item{Kind: KindText, R: Rect{x, l.y, w, h}, Text: s, Font: f, Color: c, Wrap: true, Mono: f == FontMono})
	return h
}

// button adds a button of width w at x; primary is yellow with charcoal text.
func (l *layout) button(x, w float64, label, action string, primary, large bool) float64 {
	f, h := FontButton, 30.0
	if large {
		f, h = FontButtonLg, 38.0
	}
	fill, hover, stroke, text := l.t.Panel2, l.t.Panel3, l.t.Border, l.t.Text
	if primary {
		fill, hover, stroke, text = Accent, AccentHi, color.NRGBA{}, OnAccent
	}
	busy := l.in.Busy != ""
	if busy {
		fill, hover, text = alpha(fill, 0.5), alpha(fill, 0.5), alpha(text, 0.6)
		action = ""
	}
	r := Rect{x, l.y, w, h}
	l.add(Item{Kind: KindBox, R: r, Fill: fill, HoverFill: hover, Stroke: stroke, Radius: radSm, Action: action, Pointer: action != ""})
	l.add(Item{Kind: KindText, R: r, Text: label, Font: f, Color: text, Align: Center, VerticalAlign: true})
	return h
}

// row adds "label ........ value" and returns its height.
func (l *layout) row(x, w float64, label, value string, mono bool) float64 {
	lw, lh := l.m.Measure(label, FontBody, 0)
	vf := FontStrong
	if mono {
		vf = FontMono
	}
	vw := w - lw - 12
	_, vh := l.m.Measure(value, vf, vw)
	l.add(Item{Kind: KindText, R: Rect{x, l.y, lw + 1, lh}, Text: label, Font: FontBody, Color: l.t.Text2})
	l.add(Item{Kind: KindText, R: Rect{x + lw + 12, l.y, vw, vh}, Text: value, Font: vf, Color: l.t.Text, Align: Right, Wrap: true, Mono: mono})
	return math.Max(lh, vh)
}

// notice adds a tinted box with a text.
func (l *layout) notice(x, w float64, c color.NRGBA, s string) float64 {
	_, h := l.m.Measure(s, FontBody, w-20)
	r := Rect{x, l.y, w, h + 20}
	l.add(Item{Kind: KindBox, R: r, Fill: alpha(c, 0.10), Stroke: alpha(c, 0.30), Radius: radSm})
	l.add(Item{Kind: KindText, R: Rect{x + 10, l.y + 10, w - 20, h}, Text: s, Font: FontBody, Color: l.t.Text, Wrap: true})
	return r.H
}

// card runs body inside a card: body lays out at l.y from x with width w and
// returns nothing; the card's height follows what it added.
func (l *layout) card(body func(x, w float64)) {
	top := l.y
	i := len(l.items)
	l.add(Item{}) // the card's box, filled in below
	l.y += cardPad
	body(pad+cardPad, panelW-2*pad-2*cardPad)
	l.y += cardPad
	l.items[i] = Item{Kind: KindBox, R: Rect{pad, top, panelW - 2*pad, l.y - top}, Fill: l.t.Panel, Stroke: l.t.Border, Radius: radius}
}

// LayoutPanel lays out the panel for a state.
func LayoutPanel(in PanelInput, m Measurer, t Theme) Panel {
	l := &layout{t: t, m: m, in: in, y: pad}
	v := Describe(in.Status, in.Err)
	s := in.Status
	cw := panelW - 2*pad

	// header: tile, wordmark, pill
	l.add(Item{Kind: KindTile, R: Rect{pad, l.y, 30, 30}, Fill: t.LogoGround, Stroke: t.LogoMark})
	_, wh := m.Measure("BoundGate", FontWordmark, 0)
	l.add(Item{Kind: KindText, R: Rect{pad + 40, l.y + (30-wh)/2, 150, wh}, Text: "BoundGate", Font: FontWordmark, Color: t.Text})
	label, tone := pillOf(v.Phase, in.Busy, t)
	pw, ph := m.Measure(label, FontPill, 0)
	pr := Rect{panelW - pad - (pw + 18 + 13), l.y + (30-(ph+8))/2, pw + 18 + 13, ph + 8}
	l.add(Item{Kind: KindBox, R: pr, Fill: alpha(tone, 0.13), Stroke: alpha(tone, 0.35), Radius: pr.H / 2})
	l.add(Item{Kind: KindDot, R: Rect{pr.X + 9, pr.Y + pr.H/2 - 3.5, 7, 7}, Fill: tone})
	pc := tone
	if tone == Accent {
		pc = t.Text
	}
	l.add(Item{Kind: KindText, R: Rect{pr.X + 22, pr.Y + 4, pw + 2, ph}, Text: label, Font: FontPill, Color: pc})
	l.y += 30 + gap

	if in.ActionError != "" {
		l.y += l.notice(pad, cw, t.Bad, Readable(in.ActionError)) + gap
	}
	if s != nil && s.KeyWarning != "" {
		l.y += l.notice(pad, cw, t.Bad, "Software key: this PC's identity can be copied. "+s.KeyWarning) + gap
	}

	switch v.Phase {
	case ServiceDown:
		l.card(func(x, w float64) {
			title := "The BoundGate service does not answer"
			if in.Err != nil && isNoAccess(in.Err) {
				title = "No access to the BoundGate service"
			}
			l.y += l.text(x, w, title, FontTitle, t.Text) + 8
			l.y += l.text(x, w, v.Detail, FontBody, t.Text2)
		})
	case Unconfigured:
		l.card(func(x, w float64) {
			l.y += l.text(x, w, "Which network is this PC joining?", FontTitle, t.Text) + 8
			l.y += l.text(x, w, "Enter the address of your BoundGate control plane. Your administrator has it.", FontBody, t.Text2) + 12
			l.y += l.button(x, w, "Set up…", ActSetUp, true, true)
		})
	case NeedsEnroll:
		l.card(func(x, w float64) {
			l.y += l.text(x, w, "Request access", FontTitle, t.Text) + 10
			l.y += l.row(x, w, "Control plane", s.Control, true) + 10
			if e := s.EnrollmentError; e != "" && !strings.Contains(e, "has not been accepted yet") {
				l.y += l.notice(x, w, t.Warn, Readable(e)) + 10
			}
			l.y += l.text(x, w, "The first time, BoundGate shows the control plane's key: compare it with the one your administrator gave you.", FontSmall, t.Text2) + 12
			l.y += l.button(x, w, "Request access", ActEnroll, true, true)
		})
	case Pending:
		l.card(func(x, w float64) {
			l.y += l.text(x, w, "Waiting for your administrator", FontTitle, t.Text) + 8
			msg := "Give this fingerprint to your administrator over a channel you trust. They compare all of it before they approve this PC."
			if s.Enrollment == "confirmed" {
				msg = "Confirmed. The last step is the administrator's signature; this panel updates by itself."
			}
			l.y += l.text(x, w, msg, FontBody, t.Text2) + 12
			l.y += l.fingerprint(x, w, "Fingerprint of this PC", s.Fingerprint) + 10
			l.y += l.row(x, w, "Device name", s.NodeName, false) + 12
			l.y += l.button(x, w, "Copy fingerprint", ActCopyFP, false, false)
		})
	case Revoked:
		l.card(func(x, w float64) {
			l.y += l.text(x, w, "This device was revoked", FontTitle, t.Text) + 8
			l.y += l.text(x, w, "An administrator revoked this PC's key. A revoked key never comes back; ask your administrator how to proceed.", FontBody, t.Text2)
		})
	default:
		l.connection(v)
	}

	// footer: the device, sign out, quit
	l.y += gap
	fy := l.y
	name := ""
	if s != nil {
		name = s.NodeName
		if s.HardwareBound {
			name += " · key in the TPM"
		}
	}
	_, fh := m.Measure("Quit", FontSmall, 0)
	x := panelW - pad
	for _, a := range []struct{ label, act string }{{"Quit", ActQuit}, {"Sign out", ActSignOut}} {
		if a.act == ActSignOut && !v.CanLogout {
			continue
		}
		w, _ := m.Measure(a.label, FontSmall, 0)
		r := Rect{x - w - 12, fy - 3, w + 12, fh + 6}
		l.add(Item{Kind: KindBox, R: r, HoverFill: t.Panel2, Radius: 6, Action: a.act, Pointer: true})
		l.add(Item{Kind: KindText, R: Rect{r.X + 6, fy, w + 1, fh}, Text: a.label, Font: FontSmall, Color: t.Text2})
		x = r.X - 4
	}
	l.add(Item{Kind: KindText, R: Rect{pad + 2, fy, x - pad - 8, fh}, Text: name, Font: FontSmall, Color: t.Text3})
	l.y = fy + fh + pad
	return Panel{W: panelW, H: math.Ceil(l.y), Bg: t.Bg, Items: l.items}
}

// fingerprint adds a caption and the fingerprint in a well.
func (l *layout) fingerprint(x, w float64, caption, fp string) float64 {
	top := l.y
	_, ch := l.m.Measure(caption, FontSmall, w)
	l.add(Item{Kind: KindText, R: Rect{x, l.y, w, ch}, Text: caption, Font: FontSmall, Color: l.t.Text2})
	l.y += ch + 6
	_, fh := l.m.Measure(fp, FontMono, w-20)
	l.add(Item{Kind: KindBox, R: Rect{x, l.y, w, fh + 16}, Fill: l.t.Panel2, Stroke: l.t.Border, Radius: radSm})
	l.add(Item{Kind: KindText, R: Rect{x + 10, l.y + 8, w - 20, fh}, Text: fp, Font: FontMono, Color: l.t.Text, Wrap: true, Mono: true})
	l.y = top
	return ch + 6 + fh + 16
}

// connection: the card and buttons of an approved node, down, on its way,
// asking for a sign-in or connected.
func (l *layout) connection(v View) {
	t, s, in := l.t, l.in.Status, l.in
	cw := panelW - 2*pad
	var hub *node.HubStatus
	for i := range s.Hubs {
		if h := &s.Hubs[i]; h.State == "connected" && (hub == nil || h.Primary) {
			hub = h
		}
	}
	l.card(func(x, w float64) {
		switch v.Phase {
		case Connected:
			_, bh := l.m.Measure(s.OverlayIP, FontBig, 0)
			l.add(Item{Kind: KindText, R: Rect{x, l.y, w * 0.7, bh}, Text: s.OverlayIP, Font: FontBig, Color: t.Text})
			if !s.Since.IsZero() {
				since := "since " + ago(in.Now.Sub(s.Since))
				_, sh := l.m.Measure(since, FontSmall, 0)
				l.add(Item{Kind: KindText, R: Rect{x, l.y + bh - sh - 2, w, sh}, Text: since, Font: FontSmall, Color: t.Text3, Align: Right})
			}
			l.y += bh + 10
			through := "–"
			if hub != nil {
				through = hub.Name
				if hub.Transport == "tcp" {
					through += " · over TCP"
				}
			}
			l.y += l.row(x, w, "Through", through, false) + 6
			if s.User != nil {
				l.y += l.row(x, w, "Signed in as", firstNonEmpty(s.User.Username, s.User.Email, s.User.Subject), false) + 6
			}
			l.y += l.row(x, w, "Networks", networks(s.Routes), false)
			if in.Rate.Valid {
				l.y += 6
				l.y += l.row(x, w, "Now", fmt.Sprintf("↓ %s/s  ↑ %s/s", Bytes(uint64(in.Rate.In)), Bytes(uint64(in.Rate.Out))), false)
			}
		case LoginRequired:
			l.y += l.text(x, w, "Sign in to finish connecting", FontTitle, t.Text) + 8
			msg := "The network wants to know who is using this PC."
			if in.Busy == "Signing in" {
				msg = "Continue in your browser. This panel updates when you are done."
			}
			l.y += l.text(x, w, msg, FontBody, t.Text2)
		case Connecting:
			l.y += l.text(x, w, "Connecting…", FontTitle, t.Text)
			for _, h := range s.Hubs {
				state := h.State
				if h.Error != "" {
					state = Readable(h.Error)
				}
				l.y += 8
				l.y += l.row(x, w, h.Name, state, false)
			}
		default:
			l.y += l.text(x, w, "Not connected", FontTitle, t.Text)
			if len(in.Profiles) > 1 {
				l.y += 12
				l.y += l.profiles(x, w)
			}
		}
		for _, r := range s.SkippedRoutes {
			l.y += 10
			l.y += l.notice(x, w, t.Warn, "Not routed: "+r)
		}
		if v.Phase != Connected && s.LastError != "" {
			l.y += 10
			l.y += l.notice(x, w, t.Bad, Readable(s.LastError))
		}
		if s.BindingError != "" {
			l.y += 10
			l.y += l.notice(x, w, t.Bad, "This PC's approval does not verify: "+s.BindingError)
		}
		if s.ControlError != "" {
			l.y += 10
			l.y += l.notice(x, w, t.Warn, "Control plane: "+Readable(s.ControlError))
		}
		// details, closed until opened
		l.y += 12
		l.add(Item{Kind: KindBox, R: Rect{x, l.y, w, 1}, Fill: t.Border})
		l.y += 8
		label := "Details"
		if in.DetailsOpen {
			label = "Hide details"
		}
		_, dh := l.m.Measure(label, FontSmall, 0)
		dr := Rect{x - 6, l.y - 3, w + 12, dh + 6}
		l.add(Item{Kind: KindBox, R: dr, HoverFill: t.Panel2, Radius: 6, Action: ActDetails, Pointer: true})
		l.add(Item{Kind: KindText, R: Rect{x, l.y, w, dh}, Text: label, Font: FontSmall, Color: t.Text2})
		chev := "right"
		if in.DetailsOpen {
			chev = "down"
		}
		l.add(Item{Kind: KindChevron, R: Rect{x + w - 9, l.y + dh/2 - 4.5, 9, 9}, Text: chev, Fill: t.Text3})
		l.y += dh
		if in.DetailsOpen {
			for _, d := range Details(s, in.Rate) {
				k, val, _ := strings.Cut(d, ": ")
				// a hub's line carries state, protocol and counters: two rows
				if st, counters, ok := strings.Cut(val, "), "); ok && strings.HasPrefix(k, "Hub ") {
					l.y += 6
					l.y += l.rowSmall(x, w, k, strings.Replace(st, " (", " · ", 1))
					k, val = "", counters
				}
				l.y += 6
				l.y += l.rowSmall(x, w, k, val)
			}
		}
	})
	l.y += gap
	switch v.Phase {
	case Ready:
		l.y += l.button(pad, cw, "Connect", ActConnect, true, true)
	case LoginRequired:
		half := (cw - 8) / 2
		signIn := "Sign in"
		if in.Busy == "Signing in" {
			signIn = "Waiting for the browser…"
		}
		l.button(pad, half, signIn, ActSignIn, true, true)
		l.y += l.button(pad+half+8, half, "Disconnect", ActDisconnect, false, true)
	default:
		l.y += l.button(pad, cw, "Disconnect", ActDisconnect, false, true)
	}
}

// profiles: a pill per profile, the current one filled.
func (l *layout) profiles(x, w float64) float64 {
	t := l.t
	_, lh := l.m.Measure("Route", FontBody, 0)
	l.add(Item{Kind: KindText, R: Rect{x, l.y, w, lh}, Text: "Route", Font: FontBody, Color: t.Text2})
	top := l.y
	l.y += lh + 8
	cx, rowH := x, 0.0
	current := l.in.Status.Profile
	for _, p := range l.in.Profiles {
		pw, ph := l.m.Measure(p, FontStrong, 0)
		bw, bh := pw+20, ph+10
		if cx+bw > x+w && cx > x {
			cx = x
			l.y += rowH + 6
		}
		fill, stroke, text := t.Panel2, t.Border, t.Text
		if p == current {
			fill, stroke, text = Accent, color.NRGBA{}, OnAccent
		}
		r := Rect{cx, l.y, bw, bh}
		l.add(Item{Kind: KindBox, R: r, Fill: fill, HoverFill: fill, Stroke: stroke, Radius: bh / 2, Action: ActProfile + p, Pointer: p != current})
		l.add(Item{Kind: KindText, R: r, Text: p, Font: FontStrong, Color: text, Align: Center, VerticalAlign: true})
		cx += bw + 6
		rowH = math.Max(rowH, bh)
	}
	h := l.y + rowH - top
	l.y = top
	return h
}

// rowSmall: a details line, label and value in the small face.
func (l *layout) rowSmall(x, w float64, label, value string) float64 {
	lw, lh := l.m.Measure(label, FontSmall, 0)
	vw := w - lw - 12
	mono := label == "Fingerprint"
	f := FontSmall
	if mono {
		f = FontMono
	}
	_, vh := l.m.Measure(value, f, vw)
	l.add(Item{Kind: KindText, R: Rect{x, l.y, lw + 1, lh}, Text: label, Font: FontSmall, Color: l.t.Text3})
	l.add(Item{Kind: KindText, R: Rect{x + lw + 12, l.y, vw, vh}, Text: value, Font: f, Color: l.t.Text2, Align: Right, Wrap: true, Mono: mono})
	return math.Max(lh, vh)
}

func pillOf(p Phase, busy string, t Theme) (string, color.NRGBA) {
	if busy != "" {
		return busy + "…", Accent
	}
	switch p {
	case Connected:
		return "Connected", t.Ok
	case Connecting:
		return "Connecting", Accent
	case LoginRequired:
		return "Sign-in needed", Accent
	case Ready:
		return "Disconnected", t.Text3
	case Pending:
		return "Awaiting approval", Accent
	case Revoked:
		return "Revoked", t.Bad
	case NeedsEnroll, Unconfigured:
		return "Setup", Accent
	}
	return "Service off", t.Text3
}

func isNoAccess(err error) bool {
	return err != nil && strings.Contains(err.Error(), ErrNoAccess.Error())
}

func networks(r []string) string {
	switch {
	case len(r) == 0:
		return "none"
	case len(r) <= 2:
		return strings.Join(r, ", ")
	}
	return fmt.Sprintf("%s, %s +%d", r[0], r[1], len(r)-2)
}

func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h %d min", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// Readable shortens what the daemon reports for a log (the whole chain, with
// the request in it) to its last link, as the Mac app's readable() does.
func Readable(e string) string {
	s := e
	for _, verb := range []string{"Get \"", "Post \"", "Put \"", "Delete \"", "Head \""} {
		if i := strings.Index(s, verb); i >= 0 {
			if j := strings.Index(s[i+len(verb):], "\": "); j >= 0 {
				s = s[i+len(verb)+j+3:]
			}
		}
	}
	for _, p := range []string{"transport: ", "pin control plane key: ", "controlclient: "} {
		s = strings.TrimPrefix(s, p)
	}
	if s == "" {
		return e
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// --- painting ----------------------------------------------------------------

// Paint draws the panel's boxes, tile and dots at scale (pixels per unit)
// onto img, whose size is the panel's at that scale. Text is the platform's.
func Paint(img *image.NRGBA, p Panel, scale float64, hover string) {
	fillRect(img, img.Bounds(), p.Bg)
	for _, it := range p.Items {
		switch it.Kind {
		case KindBox:
			fill := it.Fill
			if hover != "" && it.Action == hover && it.HoverFill.A != 0 {
				fill = it.HoverFill
			}
			roundRect(img, it.R, it.Radius, scale, fill, it.Stroke)
		case KindDot:
			roundRect(img, it.R, it.R.W/2, scale, it.Fill, color.NRGBA{})
		case KindTile:
			tile(img, it.R, scale, it.Fill, it.Stroke)
		case KindChevron:
			chevron(img, it.R, scale, it.Fill, it.Text == "down")
		}
	}
}

func fillRect(img *image.NRGBA, r image.Rectangle, c color.NRGBA) {
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			img.SetNRGBA(x, y, c)
		}
	}
}

// roundRect fills and outlines (1 px) a rounded rectangle, antialiased.
func roundRect(img *image.NRGBA, r Rect, rad, scale float64, fill, stroke color.NRGBA) {
	if fill.A == 0 && stroke.A == 0 {
		return
	}
	x0, y0, x1, y1 := r.X*scale, r.Y*scale, (r.X+r.W)*scale, (r.Y+r.H)*scale
	rad = math.Min(rad*scale, math.Min(x1-x0, y1-y0)/2)
	cx, cy, hx, hy := (x0+x1)/2, (y0+y1)/2, (x1-x0)/2, (y1-y0)/2
	sd := func(px, py float64) float64 { // signed distance, negative inside
		qx := math.Abs(px-cx) - (hx - rad)
		qy := math.Abs(py-cy) - (hy - rad)
		return math.Hypot(math.Max(qx, 0), math.Max(qy, 0)) + math.Min(math.Max(qx, qy), 0) - rad
	}
	lw := math.Max(1, math.Round(scale))
	b := img.Bounds()
	for y := int(math.Floor(y0)); y < int(math.Ceil(y1)); y++ {
		for x := int(math.Floor(x0)); x < int(math.Ceil(x1)); x++ {
			if !(image.Point{x, y}).In(b) {
				continue
			}
			d := sd(float64(x)+0.5, float64(y)+0.5)
			var in, edge float64
			if d < -lw-1 || d > 1 { // clearly inside or outside: one sample
				if d < 0 {
					in = 1
				}
			} else {
				const ss = 4
				for sy := 0; sy < ss; sy++ {
					for sx := 0; sx < ss; sx++ {
						dd := sd(float64(x)+(float64(sx)+0.5)/ss, float64(y)+(float64(sy)+0.5)/ss)
						if dd <= 0 {
							in++
							if dd > -lw {
								edge++
							}
						}
					}
				}
				in, edge = in/(ss*ss), edge/(ss*ss)
			}
			if in == 0 {
				continue
			}
			if fill.A != 0 {
				blend(img, x, y, fill, in)
			}
			if stroke.A != 0 && edge > 0 {
				blend(img, x, y, stroke, edge)
			}
		}
	}
}

// tile: the logo tile, a rounded square with the mark (docs/assets/logo.svg).
func tile(img *image.NRGBA, r Rect, scale float64, ground, mark color.NRGBA) {
	roundRect(img, r, r.W*232/1024, scale, ground, color.NRGBA{})
	s := r.W * scale / 1024
	ox, oy := r.X*scale, r.Y*scale
	lw := 57 * s * 1.25 // a bit heavier than the 1024 grid: the tile is small
	frames := []rrect{{148, 268, 462, 300, 76}, {414, 456, 462, 300, 76}}
	for y := int(oy); y < int(math.Ceil(oy+r.H*scale)); y++ {
		for x := int(ox); x < int(math.Ceil(ox+r.W*scale)); x++ {
			const ss = 4
			var c float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/ss - ox) / s
					py := (float64(y) + (float64(sy)+0.5)/ss - oy) / s
					for _, f := range frames {
						if f.onStroke(px, py, lw/s) {
							c++
							break
						}
					}
				}
			}
			if c > 0 {
				blend(img, x, y, mark, c/(ss*ss))
			}
		}
	}
}

// chevron: a small open arrow, pointing right or down, round ends.
func chevron(img *image.NRGBA, r Rect, scale float64, c color.NRGBA, down bool) {
	pts := [3][2]float64{{0.3, 0.1}, {0.7, 0.5}, {0.3, 0.9}}
	if down {
		pts = [3][2]float64{{0.1, 0.3}, {0.5, 0.7}, {0.9, 0.3}}
	}
	x0, y0, w := r.X*scale, r.Y*scale, r.W*scale
	half := 0.75 * scale // 1.5 units stroke
	seg := func(px, py float64, a, b [2]float64) float64 {
		ax, ay, bx, by := x0+a[0]*w, y0+a[1]*w, x0+b[0]*w, y0+b[1]*w
		dx, dy := bx-ax, by-ay
		t := math.Max(0, math.Min(1, ((px-ax)*dx+(py-ay)*dy)/(dx*dx+dy*dy)))
		return math.Hypot(px-ax-t*dx, py-ay-t*dy)
	}
	for y := int(y0) - 1; y < int(math.Ceil(y0+w))+1; y++ {
		for x := int(x0) - 1; x < int(math.Ceil(x0+w))+1; x++ {
			if !(image.Point{x, y}).In(img.Bounds()) {
				continue
			}
			const ss = 4
			var cov float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px, py := float64(x)+(float64(sx)+0.5)/ss, float64(y)+(float64(sy)+0.5)/ss
					if math.Min(seg(px, py, pts[0], pts[1]), seg(px, py, pts[1], pts[2])) <= half {
						cov++
					}
				}
			}
			if cov > 0 {
				blend(img, x, y, c, cov/(ss*ss))
			}
		}
	}
}

// blend puts c with coverage cov (0..1) over the pixel, which is opaque.
func blend(img *image.NRGBA, x, y int, c color.NRGBA, cov float64) {
	a := float64(c.A) / 255 * cov
	if a <= 0 {
		return
	}
	d := img.NRGBAAt(x, y)
	mix := func(s, t uint8) uint8 { return uint8(float64(s)*a + float64(t)*(1-a) + 0.5) }
	img.SetNRGBA(x, y, color.NRGBA{mix(c.R, d.R), mix(c.G, d.G), mix(c.B, d.B), 0xff})
}

// SamplePanels are the panel's phases with made-up data: for its tests and
// for looking at it (boundgate-tray -render-panel).
func SamplePanels(now time.Time) map[string]PanelInput {
	fp := "caad b839 1978 0978 76ed 28e9 b1af 430e e7ca 18d1 5a43 3a95 b755 08ac 7e28 8d6b"
	up := &node.Status{State: node.StateUp, Enrollment: "approved", OverlayIP: "10.25.0.4", NodeName: "DESKTOP-Q8EUT8R", HardwareBound: true,
		Since: now.Add(-12 * time.Minute), Routes: []string{"0.0.0.0/1", "128.0.0.0/1"}, User: &node.UserStatus{Username: "offerman"},
		Hubs:    []node.HubStatus{{Name: "hub-pvpn", State: "connected", Transport: "quic", Primary: true, TunnelStats: transport.TunnelStats{BytesIn: 19549805, BytesOut: 725769}}},
		Control: "vpn.net407.com:443", ControlTransport: "h3", KeyKind: "tpm2", Interface: "BoundGate", MTU: 1280, Profile: "full", Fingerprint: fp, Version: "v0.1.11"}
	return map[string]PanelInput{
		"service":      {Err: errors.New("node daemon not reachable at x: refused"), Now: now},
		"unconfigured": {Status: &node.Status{State: "unconfigured", NodeName: "DESKTOP-Q8EUT8R", HardwareBound: true}, Now: now},
		"enroll":       {Status: &node.Status{State: node.StateDown, Enrollment: "unknown", Control: "vpn.net407.com:443", NodeName: "DESKTOP-Q8EUT8R", HardwareBound: true}, Now: now},
		"pending":      {Status: &node.Status{State: node.StateDown, Enrollment: "pending", NodeName: "DESKTOP-Q8EUT8R", HardwareBound: true, Fingerprint: fp}, Now: now},
		"ready":        {Status: &node.Status{State: node.StateDown, Enrollment: "approved", Profile: "full", NodeName: "DESKTOP-Q8EUT8R", HardwareBound: true}, Profiles: []string{"full", "lan-only"}, Now: now},
		"login":        {Status: &node.Status{State: node.StateUp, Enrollment: "approved", LoginRequired: true, NodeName: "DESKTOP-Q8EUT8R", HardwareBound: true}, Now: now},
		"connected":    {Status: up, Now: now, Rate: Rate{Valid: true, In: 1.2e6, Out: 48e3}},
		"details":      {Status: up, Now: now, DetailsOpen: true},
	}
}
