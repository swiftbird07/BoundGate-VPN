//go:build windows

package main

import (
	"fmt"
	"image"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/tray"
)

// The panel window: a borderless flyout above the tray icon, like Windows'
// own (network, volume). It closes when it loses the focus. internal/tray
// lays it out and paints its shapes; this file owns the window, draws the
// text with GDI (ClearType, Segoe UI) into the same bitmap and turns clicks
// into actions. It runs on its own thread with its own message loop.

var (
	dwmapi                    = windows.NewLazySystemDLL("dwmapi.dll")
	procDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
	procShowWindow            = user32.NewProc("ShowWindow")
	procSetWindowPos          = user32.NewProc("SetWindowPos")
	procPostMessageW          = user32.NewProc("PostMessageW")
	procGetCursorPos          = user32.NewProc("GetCursorPos")
	procMonitorFromPoint      = user32.NewProc("MonitorFromPoint")
	procGetMonitorInfoW       = user32.NewProc("GetMonitorInfoW")
	procGetDpiForWindow       = user32.NewProc("GetDpiForWindow")
	procBeginPaint            = user32.NewProc("BeginPaint")
	procEndPaint              = user32.NewProc("EndPaint")
	procInvalidateRect        = user32.NewProc("InvalidateRect")
	procDrawTextW             = user32.NewProc("DrawTextW")
	procTrackMouseEvent       = user32.NewProc("TrackMouseEvent")
	procSetCursor             = user32.NewProc("SetCursor")
	procCreateCompatibleDC    = gdi32.NewProc("CreateCompatibleDC")
	procDeleteDC              = gdi32.NewProc("DeleteDC")
	procSelectObject          = gdi32.NewProc("SelectObject")
	procCreateDIBSection      = gdi32.NewProc("CreateDIBSection")
	procBitBlt                = gdi32.NewProc("BitBlt")
	procSetTextColor          = gdi32.NewProc("SetTextColor")
	procSetBkMode             = gdi32.NewProc("SetBkMode")
)

const (
	wsPopup          = 0x80000000
	wsExToolWindow   = 0x00000080
	csDropShadow     = 0x00020000
	wmActivate       = 0x0006
	wmPaint          = 0x000F
	wmSetCursor      = 0x0020
	wmKeyDown        = 0x0100
	wmMouseMove      = 0x0200
	wmLButtonUp      = 0x0202
	wmMouseLeave     = 0x02A3
	wmDpiChanged     = 0x02E0
	wmApp            = 0x8000
	wmPanelToggle    = wmApp + 1
	wmPanelUpdate    = wmApp + 2
	vkEscape         = 0x1B
	swHide           = 0
	swpShowWindow    = 0x0040
	swpNoActivate    = 0x0010
	hwndTopmost      = ^uintptr(0) // -1
	idcHand          = 32649
	tmeLeave         = 0x00000002
	dtCenter         = 0x0001
	dtRight          = 0x0002
	dtVCenter        = 0x0004
	dtWordBreak      = 0x0010
	dtSingleLine     = 0x0020
	dtCalcRect       = 0x0400
	dtNoPrefix       = 0x0800
	dtEndEllipsis    = 0x8000
	dwmaDarkMode     = 20
	dwmaCornerPref   = 33
	dwmcpRound       = 2
	monitorNearest   = 2
	srccopy          = 0x00CC0020
	transparentBkgnd = 1
)

type point struct{ x, y int32 }
type rect32 struct{ left, top, right, bottom int32 }

type monitorInfo struct {
	size          uint32
	monitor, work rect32
	flags         uint32
}

type paintStruct struct {
	hdc       uintptr
	erase     int32
	rc        rect32
	restore   int32
	incUpdate int32
	reserved  [32]byte
}

type bitmapInfoHeader struct {
	size                       uint32
	width, height              int32
	planes, bitCount           uint16
	compression, sizeImage     uint32
	xPelsPerMeter, yPelsPerMtr int32
	clrUsed, clrImportant      uint32
}

type trackMouseEvent struct {
	size, flags uint32
	hwnd        uintptr
	hoverTime   uint32
}

type panelWin struct {
	onAction func(string)
	ready    chan struct{}

	mu       sync.Mutex
	in       tray.PanelInput // the latest state, from the app's poll
	hwnd     uintptr
	visible  bool
	hiddenAt time.Time
	details  bool

	// panel thread only
	layout    tray.Panel
	theme     tray.Theme
	scale     float64
	hover     string
	tracking  bool
	anchor    point // where the panel hangs: the click on the tray icon
	fonts     map[tray.Font]uintptr
	fontScale float64
	mdc       uintptr // a memory DC for measuring
}

var thePanel *panelWin

func newPanel(onAction func(string)) *panelWin {
	p := &panelWin{onAction: onAction, ready: make(chan struct{})}
	thePanel = p
	go p.loop()
	<-p.ready
	return p
}

// toggle opens the panel at the tray icon, or closes it.
func (p *panelWin) toggle() {
	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procPostMessageW.Call(p.hwnd, wmPanelToggle, uintptr(uint32(pt.x)), uintptr(uint32(pt.y)))
}

// update hands the panel the latest state; it redraws when open.
func (p *panelWin) update(in tray.PanelInput) {
	p.mu.Lock()
	p.in = in
	open := p.visible
	p.mu.Unlock()
	if open {
		procPostMessageW.Call(p.hwnd, wmPanelUpdate, 0, 0)
	}
}

func (p *panelWin) isOpen() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.visible
}

func (p *panelWin) hide() {
	procShowWindow.Call(p.hwnd, swHide)
	p.mu.Lock()
	p.visible, p.hiddenAt = false, time.Now()
	p.mu.Unlock()
	p.hover = ""
}

func (p *panelWin) loop() {
	runtime.LockOSThread()
	class, _ := windows.UTF16PtrFromString("BoundGatePanel")
	cursor, _, _ := procLoadCursorW.Call(0, idcArrow)
	wc := wndClassEx{style: csDropShadow, wndProc: windows.NewCallback(panelProc), cursor: windows.Handle(cursor), className: class}
	wc.size = uint32(unsafe.Sizeof(wc))
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	p.hwnd = create(wsExToolWindow|wsExTopmost, class, "BoundGate", wsPopup, 0, 0, 10, 10, 0, 0)
	pref := uint32(dwmcpRound)
	procDwmSetWindowAttribute.Call(p.hwnd, dwmaCornerPref, uintptr(unsafe.Pointer(&pref)), 4)
	p.mdc, _, _ = procCreateCompatibleDC.Call(0)
	close(p.ready)
	var m winMsg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func panelProc(hwnd uintptr, msg uint32, w, l uintptr) uintptr {
	p := thePanel
	switch msg {
	case wmPanelToggle:
		p.mu.Lock()
		open, recent := p.visible, time.Since(p.hiddenAt) < 400*time.Millisecond
		p.mu.Unlock()
		// a click on the icon while the panel is open first takes the focus
		// from it (it hides) and then arrives here: that click meant "close"
		if open || recent {
			if open {
				p.hide()
			}
			return 0
		}
		p.anchor = point{int32(uint32(w)), int32(uint32(l))}
		p.show()
		return 0
	case wmPanelUpdate:
		p.relayout()
		return 0
	case wmActivate:
		if w&0xffff == 0 { // WA_INACTIVE
			p.hide()
		}
		return 0
	case wmKeyDown:
		if w == vkEscape {
			p.hide()
		}
		return 0
	case wmMouseMove:
		if !p.tracking {
			tme := trackMouseEvent{flags: tmeLeave, hwnd: hwnd}
			tme.size = uint32(unsafe.Sizeof(tme))
			procTrackMouseEvent.Call(uintptr(unsafe.Pointer(&tme)))
			p.tracking = true
		}
		x, y := float64(int16(l&0xffff))/p.scale, float64(int16(l>>16&0xffff))/p.scale
		if h := p.layout.HitTest(x, y); h != p.hover {
			p.hover = h
			procInvalidateRect.Call(hwnd, 0, 0)
		}
		return 0
	case wmMouseLeave:
		p.tracking = false
		if p.hover != "" {
			p.hover = ""
			procInvalidateRect.Call(hwnd, 0, 0)
		}
		return 0
	case wmSetCursor:
		if p.hover != "" {
			c, _, _ := procLoadCursorW.Call(0, idcHand)
			procSetCursor.Call(c)
			return 1
		}
	case wmLButtonUp:
		x, y := float64(int16(l&0xffff))/p.scale, float64(int16(l>>16&0xffff))/p.scale
		p.click(p.layout.HitTest(x, y))
		return 0
	case wmDpiChanged:
		p.relayout()
		return 0
	case wmPaint:
		p.paint(hwnd)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), w, l)
	return r
}

func (p *panelWin) click(act string) {
	switch act {
	case "":
		return
	case tray.ActDetails:
		p.details = !p.details
		p.relayout()
		return
	case tray.ActSetUp, tray.ActEnroll, tray.ActSignIn, tray.ActQuit:
		// these open a window of their own (or end the tray)
		p.hide()
	}
	go p.onAction(act)
}

func (p *panelWin) show() {
	p.mu.Lock()
	p.visible = true
	p.mu.Unlock()
	p.relayout()
	procSetForegroundWnd.Call(p.hwnd)
}

// relayout lays the panel out for the latest state and fits the window to it,
// hanging from the anchor at the taskbar's edge.
func (p *panelWin) relayout() {
	p.mu.Lock()
	in, open := p.in, p.visible
	p.mu.Unlock()
	if !open {
		return
	}
	dpi, _, _ := procGetDpiForWindow.Call(p.hwnd)
	if dpi == 0 {
		dpi, _, _ = procGetDpiForSystem.Call()
	}
	p.scale = float64(dpi) / 96
	p.theme = tray.ThemeOf(appsDark())
	dark := uint32(0)
	if appsDark() {
		dark = 1
	}
	procDwmSetWindowAttribute.Call(p.hwnd, dwmaDarkMode, uintptr(unsafe.Pointer(&dark)), 4)
	in.DetailsOpen, in.Hover, in.Now = p.details, p.hover, time.Now()
	p.layout = tray.LayoutPanel(in, p, p.theme)

	w, h := int32(math.Ceil(p.layout.W*p.scale)), int32(math.Ceil(p.layout.H*p.scale))
	var mi monitorInfo
	mi.size = uint32(unsafe.Sizeof(mi))
	mon, _, _ := procMonitorFromPoint.Call(uintptr(uint32(p.anchor.x))|uintptr(uint32(p.anchor.y))<<32, monitorNearest)
	procGetMonitorInfoW.Call(mon, uintptr(unsafe.Pointer(&mi)))
	wk, mo := mi.work, mi.monitor
	gapPx := int32(12 * p.scale)
	clamp := func(v, lo, hi int32) int32 { return max(lo, min(v, hi)) }
	x := clamp(p.anchor.x-w/2, wk.left+gapPx, wk.right-w-gapPx)
	y := wk.bottom - h - gapPx // taskbar at the bottom, the usual place
	switch {
	case wk.top > mo.top:
		y = wk.top + gapPx
	case wk.left > mo.left:
		x, y = wk.left+gapPx, clamp(p.anchor.y-h/2, wk.top+gapPx, wk.bottom-h-gapPx)
	case wk.right < mo.right:
		x, y = wk.right-w-gapPx, clamp(p.anchor.y-h/2, wk.top+gapPx, wk.bottom-h-gapPx)
	}
	procSetWindowPos.Call(p.hwnd, hwndTopmost, uintptr(x), uintptr(y), uintptr(w), uintptr(h), swpShowWindow)
	procInvalidateRect.Call(p.hwnd, 0, 0)
}

// --- text --------------------------------------------------------------------

type face struct {
	name   string
	size   float64 // pixels at 96 dpi
	weight int
}

var faces = map[tray.Font]face{
	tray.FontBody:     {"Segoe UI", 12.5, 400},
	tray.FontStrong:   {"Segoe UI", 12.5, 600},
	tray.FontSmall:    {"Segoe UI", 11.5, 400},
	tray.FontPill:     {"Segoe UI", 11.5, 600},
	tray.FontTitle:    {"Segoe UI", 15.5, 700},
	tray.FontBig:      {"Segoe UI", 23, 600},
	tray.FontWordmark: {"Segoe UI", 17, 700},
	tray.FontButton:   {"Segoe UI", 13, 600},
	tray.FontButtonLg: {"Segoe UI", 14, 600},
	tray.FontMono:     {"Consolas", 12.5, 400},
}

func (p *panelWin) font(f tray.Font) uintptr {
	if p.fontScale != p.scale {
		for _, h := range p.fonts {
			procDeleteObject.Call(h)
		}
		p.fonts, p.fontScale = map[tray.Font]uintptr{}, p.scale
	}
	if h, ok := p.fonts[f]; ok {
		return h
	}
	fc := faces[f]
	name, _ := windows.UTF16PtrFromString(fc.name)
	height := -int32(math.Round(fc.size * p.scale))
	h, _, _ := procCreateFontW.Call(uintptr(height), 0, 0, 0, uintptr(fc.weight), 0, 0, 0, 1, 0, 0,
		5 /* CLEARTYPE_QUALITY */, 0, uintptr(unsafe.Pointer(name)))
	p.fonts[f] = h
	return h
}

// Measure implements tray.Measurer with GDI, in 96-dpi units.
func (p *panelWin) Measure(text string, f tray.Font, width float64) (float64, float64) {
	procSelectObject.Call(p.mdc, p.font(f))
	s := utf16z(text)
	flags := uintptr(dtCalcRect | dtNoPrefix)
	r := rect32{right: int32(math.Floor(width * p.scale))}
	if width > 0 {
		flags |= dtWordBreak
	} else {
		flags |= dtSingleLine
		r.right = 0
	}
	procDrawTextW.Call(p.mdc, uintptr(unsafe.Pointer(&s[0])), uintptr(len(s)-1), uintptr(unsafe.Pointer(&r)), flags)
	return float64(r.right-r.left) / p.scale, float64(r.bottom-r.top) / p.scale
}

// --- painting ------------------------------------------------------------------

func (p *panelWin) paint(hwnd uintptr) {
	var ps paintStruct
	hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	defer procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	w, h := int(math.Ceil(p.layout.W*p.scale)), int(math.Ceil(p.layout.H*p.scale))
	p.draw(hdc, func(mdc uintptr, _ []byte) {
		procBitBlt.Call(hdc, 0, 0, uintptr(w), uintptr(h), mdc, 0, 0, srccopy)
	})
}

// draw renders the laid-out panel into a DIB compatible with hdc (0: the
// screen) and hands it to use: the memory DC and its BGRA pixels.
func (p *panelWin) draw(hdc uintptr, use func(mdc uintptr, bgra []byte)) {
	w, h := int(math.Ceil(p.layout.W*p.scale)), int(math.Ceil(p.layout.H*p.scale))
	if w == 0 || h == 0 {
		return
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	tray.Paint(img, p.layout, p.scale, p.hover)

	bi := bitmapInfoHeader{width: int32(w), height: -int32(h), planes: 1, bitCount: 32} // top-down
	bi.size = uint32(unsafe.Sizeof(bi))
	var bits unsafe.Pointer
	bmp, _, _ := procCreateDIBSection.Call(hdc, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 {
		return
	}
	defer procDeleteObject.Call(bmp)
	px := unsafe.Slice((*byte)(bits), w*h*4)
	for i := 0; i < w*h; i++ { // RGBA → BGRA, opaque
		px[i*4], px[i*4+1], px[i*4+2], px[i*4+3] = img.Pix[i*4+2], img.Pix[i*4+1], img.Pix[i*4], 0xff
	}
	mdc, _, _ := procCreateCompatibleDC.Call(hdc)
	defer procDeleteDC.Call(mdc)
	old, _, _ := procSelectObject.Call(mdc, bmp)
	defer procSelectObject.Call(mdc, old)
	procSetBkMode.Call(mdc, transparentBkgnd)
	for _, it := range p.layout.Items {
		if it.Kind != tray.KindText || it.Text == "" {
			continue
		}
		procSelectObject.Call(mdc, p.font(it.Font))
		c := it.Color
		if c.A < 0xff { // GDI text has no alpha: mix with the ground
			a := float64(c.A) / 255
			bg := p.layout.Bg
			c.R = uint8(float64(c.R)*a + float64(bg.R)*(1-a))
			c.G = uint8(float64(c.G)*a + float64(bg.G)*(1-a))
			c.B = uint8(float64(c.B)*a + float64(bg.B)*(1-a))
		}
		procSetTextColor.Call(mdc, uintptr(c.R)|uintptr(c.G)<<8|uintptr(c.B)<<16)
		r := rect32{
			left: int32(math.Round(it.R.X * p.scale)), top: int32(math.Round(it.R.Y * p.scale)),
			right: int32(math.Round((it.R.X + it.R.W) * p.scale)), bottom: int32(math.Round((it.R.Y + it.R.H) * p.scale)),
		}
		flags := uintptr(dtNoPrefix)
		switch {
		case it.VerticalAlign:
			flags |= dtSingleLine | dtVCenter | dtEndEllipsis
		case it.Wrap:
			flags |= dtWordBreak
		default:
			flags |= dtSingleLine | dtEndEllipsis
		}
		switch it.Align {
		case tray.Center:
			flags |= dtCenter
		case tray.Right:
			flags |= dtRight
		}
		s := utf16z(it.Text)
		procDrawTextW.Call(mdc, uintptr(unsafe.Pointer(&s[0])), uintptr(len(s)-1), uintptr(unsafe.Pointer(&r)), flags)
	}
	use(mdc, px)
}

// renderPanels writes every phase of the panel as a PNG into dir, light and
// dark, at 100 % and 150 %, without a window: a look at the panel for whoever
// works on it (boundgate-tray -render-panel DIR).
func renderPanels(dir string) error {
	p := &panelWin{}
	p.mdc, _, _ = procCreateCompatibleDC.Call(0)
	defer procDeleteDC.Call(p.mdc)
	for name, in := range tray.SamplePanels(time.Now()) {
		for _, dark := range []bool{false, true} {
			for _, sc := range []float64{1, 1.5} {
				p.scale, p.theme = sc, tray.ThemeOf(dark)
				p.layout = tray.LayoutPanel(in, p, p.theme)
				var werr error
				p.draw(0, func(_ uintptr, bgra []byte) {
					w, h := int(math.Ceil(p.layout.W*p.scale)), int(math.Ceil(p.layout.H*p.scale))
					img := image.NewNRGBA(image.Rect(0, 0, w, h))
					for i := 0; i < w*h; i++ {
						img.Pix[i*4], img.Pix[i*4+1], img.Pix[i*4+2], img.Pix[i*4+3] = bgra[i*4+2], bgra[i*4+1], bgra[i*4], 0xff
					}
					theme := "light"
					if dark {
						theme = "dark"
					}
					f, err := os.Create(filepath.Join(dir, fmt.Sprintf("%s-%s-%d.png", name, theme, int(sc*100))))
					if err != nil {
						werr = err
						return
					}
					defer f.Close()
					werr = png.Encode(f, img)
				})
				if werr != nil {
					return werr
				}
			}
		}
	}
	return nil
}

// appsDark: Settings, Personalization, Colors, "app mode" is dark.
func appsDark() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("AppsUseLightTheme")
	return err == nil && v == 0
}

// utf16z converts text for GDI, NUL-terminated and never empty: a NUL
// inside the text (a name or an error the control plane sent) is dropped
// instead of failing the conversion, which would leave nothing to point at.
func utf16z(text string) []uint16 {
	s, _ := windows.UTF16FromString(strings.ReplaceAll(text, "\x00", ""))
	return s
}
