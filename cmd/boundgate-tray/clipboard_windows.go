//go:build windows

package main

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	openClipboard    = user32.NewProc("OpenClipboard")
	closeClipboard   = user32.NewProc("CloseClipboard")
	emptyClipboard   = user32.NewProc("EmptyClipboard")
	setClipboardData = user32.NewProc("SetClipboardData")
	globalAlloc      = kernel32.NewProc("GlobalAlloc")
	globalLock       = kernel32.NewProc("GlobalLock")
	globalUnlock     = kernel32.NewProc("GlobalUnlock")
	globalFree       = kernel32.NewProc("GlobalFree")
	moveMemory       = kernel32.NewProc("RtlMoveMemory")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

// setClipboard puts text on the clipboard as CF_UNICODETEXT.
func setClipboard(text string) error {
	u, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	if r, _, e := openClipboard.Call(0); r == 0 {
		return e
	}
	defer closeClipboard.Call()
	emptyClipboard.Call()
	size := uintptr(len(u) * 2)
	h, _, e := globalAlloc.Call(gmemMoveable, size)
	if h == 0 {
		return e
	}
	p, _, e := globalLock.Call(h)
	if p == 0 {
		globalFree.Call(h)
		return e
	}
	moveMemory.Call(p, uintptr(unsafe.Pointer(&u[0])), size)
	globalUnlock.Call(h)
	if r, _, _ := setClipboardData.Call(cfUnicodeText, h); r == 0 {
		globalFree.Call(h) // still ours: the clipboard did not take it
		return errors.New("the clipboard did not take the text")
	}
	return nil
}
