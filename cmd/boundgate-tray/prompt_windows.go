//go:build windows

package main

import (
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A one-line input window: the tray asks for the control plane's address
// with it. Plain Win32 like the rest of the tray, no dialog resources: a
// window with a label, an edit control and OK/Cancel, driven by its own
// message loop on its own thread. IsDialogMessage gives it Tab, Enter (OK)
// and Esc (Cancel).

var (
	gdi32                = windows.NewLazySystemDLL("gdi32.dll")
	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procIsDialogMessageW = user32.NewProc("IsDialogMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procGetWindowTextW   = user32.NewProc("GetWindowTextW")
	procSendMessageW     = user32.NewProc("SendMessageW")
	procSetForegroundWnd = user32.NewProc("SetForegroundWindow")
	procSetFocus         = user32.NewProc("SetFocus")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procLoadCursorW      = user32.NewProc("LoadCursorW")
	procGetDpiForSystem  = user32.NewProc("GetDpiForSystem")
	procCreateFontW      = gdi32.NewProc("CreateFontW")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
)

const (
	wsCaption       = 0x00C00000
	wsSysMenu       = 0x00080000
	wsVisible       = 0x10000000
	wsChild         = 0x40000000
	wsTabStop       = 0x00010000
	wsExTopmost     = 0x00000008
	wsExDlgModal    = 0x00000001
	wsExClientEdge  = 0x00000200
	esAutoHScroll   = 0x0080
	esLowercase     = 0x0010
	bsDefPushButton = 0x0001
	wmDestroy       = 0x0002
	wmClose         = 0x0010
	wmSetFont       = 0x0030
	wmCommand       = 0x0111
	emSetSel        = 0x00B1
	idOK            = 1
	idCancel        = 2
	colorBtnFace    = 15
	idcArrow        = 32512
)

type wndClassEx struct {
	size, style         uint32
	wndProc             uintptr
	clsExtra, wndExtra  int32
	instance, icon      windows.Handle
	cursor, background  windows.Handle
	menuName, className *uint16
	iconSm              windows.Handle
}

type winMsg struct {
	hwnd           uintptr
	message        uint32
	wParam, lParam uintptr
	time           uint32
	x, y           int32
	private        uint32
}

// one prompt at a time: the tray runs one action at a time (app.run)
var (
	promptOnce  sync.Once
	promptClass *uint16
	promptState struct {
		edit       uintptr
		text       string
		ok, closed bool
	}
)

func promptProc(hwnd uintptr, msg uint32, w, l uintptr) uintptr {
	switch msg {
	case wmCommand:
		switch w & 0xffff {
		case idOK:
			promptState.text, promptState.ok = windowText(promptState.edit), true
			procDestroyWindow.Call(hwnd)
			return 0
		case idCancel:
			procDestroyWindow.Call(hwnd)
			return 0
		}
	case wmClose:
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		promptState.closed = true
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), w, l)
	return r
}

// prompt shows title, a label and an edit field with value, and returns
// what was entered; ok is false on Cancel, Esc or closing the window.
// lowercase makes the field lowercase every letter as it is typed.
func prompt(title, label, value string, lowercase bool) (text string, ok bool) {
	runtime.LockOSThread() // the window and its loop live on this thread
	defer runtime.UnlockOSThread()
	promptOnce.Do(func() {
		promptClass, _ = windows.UTF16PtrFromString("BoundGatePrompt")
		cursor, _, _ := procLoadCursorW.Call(0, idcArrow)
		wc := wndClassEx{
			wndProc:    windows.NewCallback(promptProc),
			cursor:     windows.Handle(cursor),
			background: colorBtnFace + 1,
			className:  promptClass,
		}
		wc.size = uint32(unsafe.Sizeof(wc))
		procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	})
	promptState.edit, promptState.text, promptState.ok, promptState.closed = 0, "", false, false

	// the tray is DPI aware (its manifest, gen_rsrc.go): sizes are pixels,
	// laid out at 96 dpi and scaled here
	dpi, _, _ := procGetDpiForSystem.Call()
	if dpi == 0 {
		dpi = 96
	}
	px := func(v int32) int32 { return v * int32(dpi) / 96 }
	w, h := px(480), px(178)
	sx, _, _ := procGetSystemMetrics.Call(0)
	sy, _, _ := procGetSystemMetrics.Call(1)
	hwnd := create(wsExTopmost|wsExDlgModal, promptClass, title, wsCaption|wsSysMenu|wsVisible,
		(int32(sx)-w)/2, (int32(sy)-h)/2, w, h, 0, 0)
	if hwnd == 0 {
		return "", false
	}
	// Segoe UI 9 pt, the face of Windows' own dialogs
	face, _ := windows.UTF16PtrFromString("Segoe UI")
	font, _, _ := procCreateFontW.Call(uintptr(-px(12)), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(face)))
	defer procDeleteObject.Call(font)
	static, _ := windows.UTF16PtrFromString("STATIC")
	edit, _ := windows.UTF16PtrFromString("EDIT")
	button, _ := windows.UTF16PtrFromString("BUTTON")
	style := uint32(wsChild | wsVisible | wsTabStop | esAutoHScroll)
	if lowercase {
		style |= esLowercase
	}
	ctrls := []uintptr{
		create(0, static, label, wsChild|wsVisible, px(20), px(16), px(430), px(40), hwnd, 0),
		create(wsExClientEdge, edit, value, style, px(20), px(62), px(430), px(26), hwnd, 0),
		create(0, button, "OK", wsChild|wsVisible|wsTabStop|bsDefPushButton, px(268), px(102), px(88), px(28), hwnd, idOK),
		create(0, button, "Cancel", wsChild|wsVisible|wsTabStop, px(362), px(102), px(88), px(28), hwnd, idCancel),
	}
	for _, c := range ctrls {
		procSendMessageW.Call(c, wmSetFont, font, 1)
	}
	promptState.edit = ctrls[1]
	procSendMessageW.Call(promptState.edit, emSetSel, 0, ^uintptr(0)) // select the value: typing replaces it
	procSetForegroundWnd.Call(hwnd)
	procSetFocus.Call(promptState.edit)

	var m winMsg
	for !promptState.closed {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if d, _, _ := procIsDialogMessageW.Call(hwnd, uintptr(unsafe.Pointer(&m))); d == 0 {
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}
	return promptState.text, promptState.ok
}

func create(exStyle uint32, class *uint16, text string, style uint32, x, y, w, h int32, parent, id uintptr) uintptr {
	t, _ := windows.UTF16PtrFromString(text)
	r, _, _ := procCreateWindowExW.Call(uintptr(exStyle), uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(t)),
		uintptr(style), uintptr(x), uintptr(y), uintptr(w), uintptr(h), parent, id, 0, 0)
	return r
}

func windowText(hwnd uintptr) string {
	buf := make([]uint16, 512)
	n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf[:n])
}
