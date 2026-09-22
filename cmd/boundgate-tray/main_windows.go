//go:build windows

// boundgate-tray is the Windows tray app: a frontend for the BoundGate
// service (boundgate-node, running as SYSTEM) over its socket, like the Mac
// app for the LaunchDaemon. It shows the state, connects and disconnects,
// signs in through the browser, requests access and shows the details. It
// holds no key and no secret; everything it can do, the socket's DACL lets it
// (docs/WINDOWS.md).
//go:generate go run gen_rsrc.go

package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/ipc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/tray"
)

const (
	maxProfiles = 8
	maxDetails  = 20
	idYes       = 6 // MessageBox answer
)

func main() {
	socket := flag.String("socket", ipc.DefaultSocket(), "the service's socket")
	flag.Parse()
	// one tray per session: a second start (autostart plus a click) ends here
	name, _ := windows.UTF16PtrFromString(`Local\BoundGateTray`)
	if _, err := windows.CreateMutex(nil, false, name); errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return
	}
	a := &app{client: ipc.NewClient(*socket)}
	systray.Run(a.ready, func() {})
}

type app struct {
	client *ipc.Client

	title, detail                        *systray.MenuItem
	connect, disconnect, signIn, signOut *systray.MenuItem
	enroll, setup, profileMenu           *systray.MenuItem
	details, copyFP                      *systray.MenuItem
	profiles                             [maxProfiles]*systray.MenuItem
	detailLines                          [maxDetails]*systray.MenuItem

	mu     sync.Mutex
	busy   string // the action in flight
	status *node.Status
	names  []string
	last   tray.Reading

	// draw serializes refresh: the poll and the end of an action both redraw
	draw      sync.Mutex
	lastColor tray.Color
	lastLight bool
	iconSet   bool
}

func (a *app) ready() {
	systray.SetTitle("BoundGate")
	a.title = systray.AddMenuItem("BoundGate", "")
	a.title.Disable()
	a.detail = systray.AddMenuItem("", "")
	a.detail.Disable()
	systray.AddSeparator()
	a.connect = systray.AddMenuItem("Connect", "Bring the tunnel up")
	a.disconnect = systray.AddMenuItem("Disconnect", "Take the tunnel down")
	a.signIn = systray.AddMenuItem("Sign in…", "Sign in with your organization's account in the browser")
	a.signOut = systray.AddMenuItem("Sign out", "End the user session on this device")
	a.setup = systray.AddMenuItem("Set up…", "Enter your organization's control plane")
	a.enroll = systray.AddMenuItem("Request access…", "Enroll this device with the control plane")
	a.profileMenu = systray.AddMenuItem("Profile", "Which networks go through BoundGate")
	for i := range a.profiles {
		a.profiles[i] = a.profileMenu.AddSubMenuItemCheckbox("", "", false)
		a.profiles[i].Hide()
		go a.onClick(a.profiles[i].ClickedCh, func() { a.pickProfile(i) })
	}
	systray.AddSeparator()
	a.details = systray.AddMenuItem("Details", "Traffic, protocols, device key")
	for i := range a.detailLines {
		a.detailLines[i] = a.details.AddSubMenuItem("", "")
		a.detailLines[i].Disable()
		a.detailLines[i].Hide()
	}
	a.details.AddSeparator()
	a.copyFP = a.details.AddSubMenuItem("Copy fingerprint", "The device fingerprint your administrator compares")
	systray.AddSeparator()
	quit := systray.AddMenuItem("Quit BoundGate tray", "The service keeps running; the tunnel stays as it is")

	go a.onClick(a.connect.ClickedCh, func() { a.up("") })
	go a.onClick(a.disconnect.ClickedCh, func() { a.run("Disconnecting", func() error { _, err := a.client.Down(); return err }) })
	go a.onClick(a.signIn.ClickedCh, a.login)
	go a.onClick(a.signOut.ClickedCh, func() { a.run("Signing out", func() error { _, err := a.client.Logout(); return err }) })
	go a.onClick(a.enroll.ClickedCh, a.requestAccess)
	go a.onClick(a.setup.ClickedCh, a.setUp)
	go a.onClick(a.copyFP.ClickedCh, a.copyFingerprint)
	go a.onClick(quit.ClickedCh, systray.Quit)

	go func() {
		for {
			a.refresh()
			time.Sleep(2 * time.Second)
		}
	}()
}

func (a *app) onClick(ch <-chan struct{}, f func()) {
	for range ch {
		f()
	}
}

// refresh polls the service and redraws the menu.
func (a *app) refresh() {
	a.draw.Lock()
	defer a.draw.Unlock()
	s, err := a.client.Status()
	var st *node.Status
	if err == nil {
		st = &s
	} else if errors.Is(err, windows.WSAEACCES) {
		err = tray.ErrNoAccess
	}
	var names []string
	if st != nil && st.Enrollment == "approved" {
		names, _ = a.client.Profiles()
	}
	now := tray.ReadingOf(st, time.Now())

	a.mu.Lock()
	rate := tray.RateOf(a.last, now)
	a.last, a.status, a.names = now, st, names
	busy := a.busy
	a.mu.Unlock()

	v := tray.Describe(st, err)
	light := taskbarLight()
	if !a.iconSet || v.Color != a.lastColor || light != a.lastLight {
		// loaded at the large icon size, shown at the small one (tray.Icon)
		big, _, _ := procGetSystemMetrics.Call(smCXIcon)
		small, _, _ := procGetSystemMetrics.Call(smCXSmIcon)
		systray.SetIcon(tray.Icon(v.Color, light, int(big), int(small)))
		a.iconSet, a.lastColor, a.lastLight = true, v.Color, light
	}
	systray.SetTooltip(v.Tooltip())
	title := v.Title
	if busy != "" {
		title = busy + "…"
	}
	a.title.SetTitle(title)
	if v.Detail != "" {
		a.detail.SetTitle(clip(v.Detail, 90))
		a.detail.Show()
	} else {
		a.detail.Hide()
	}
	idle := busy == ""
	show(a.connect, v.CanUp, idle)
	show(a.disconnect, v.CanDown, idle)
	show(a.signIn, v.CanLogin, idle)
	show(a.signOut, v.CanLogout, idle)
	show(a.enroll, v.CanEnroll, idle)
	show(a.setup, v.CanSetup, idle)

	current := ""
	if st != nil {
		current = st.Profile
	}
	show(a.profileMenu, len(names) > 1, idle)
	for i, it := range a.profiles {
		if i >= len(names) {
			it.Hide()
			continue
		}
		it.SetTitle(names[i])
		if names[i] == current {
			it.Check()
		} else {
			it.Uncheck()
		}
		it.Show()
	}

	lines := tray.Details(st, rate)
	show(a.details, len(lines) > 0, true)
	for i, it := range a.detailLines {
		if i < len(lines) {
			it.SetTitle(lines[i])
			it.Show()
		} else {
			it.Hide()
		}
	}
}

func show(it *systray.MenuItem, visible, enabled bool) {
	if !visible {
		it.Hide()
		return
	}
	if enabled {
		it.Enable()
	} else {
		it.Disable()
	}
	it.Show()
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// run does one action at a time and reports its error in a message box.
func (a *app) run(label string, f func() error) {
	a.mu.Lock()
	if a.busy != "" {
		a.mu.Unlock()
		return
	}
	a.busy = label
	a.mu.Unlock()
	go func() {
		err := f()
		a.mu.Lock()
		a.busy = ""
		a.mu.Unlock()
		a.refresh()
		if err != nil {
			message(label, err.Error(), windows.MB_ICONERROR)
		}
	}()
}

func (a *app) up(profile string) {
	a.run("Connecting", func() error { _, err := a.client.Up(profile); return err })
}

func (a *app) pickProfile(i int) {
	a.mu.Lock()
	var name, current string
	if i < len(a.names) {
		name = a.names[i]
	}
	if a.status != nil {
		current = a.status.Profile
	}
	down := a.status == nil || a.status.State == node.StateDown
	a.mu.Unlock()
	if name == "" || name == current {
		return
	}
	a.run("Switching to "+name, func() error {
		if !down {
			if _, err := a.client.Down(); err != nil {
				return err
			}
		}
		_, err := a.client.Up(name)
		return err
	})
}

// login opens the control plane's sign-in page in the browser and waits for
// the result, like `boundgatectl login`.
func (a *app) login() {
	a.run("Signing in", func() error {
		start, err := a.client.Login()
		if err != nil {
			return err
		}
		u, err := url.Parse(start.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return errors.New("the control plane sent no usable sign-in address")
		}
		if err := openBrowser(u.String()); err != nil {
			return fmt.Errorf("open the browser: %w", err)
		}
		deadline := time.Now().Add(5 * time.Minute)
		for time.Now().Before(deadline) {
			st, err := a.client.LoginWait(start.FlowID, 25*time.Second)
			if err != nil {
				return err
			}
			switch st.Status {
			case "pending":
				continue
			case "failed":
				if st.Error != "" {
					return errors.New(st.Error)
				}
				return errors.New("the sign-in failed")
			}
			return nil
		}
		return errors.New("the sign-in took too long")
	})
}

// setUp asks for the control plane's address, stores it (the service
// leaves its setup mode) and requests access right away, as the Mac app does.
// The field lowercases what is typed: the control plane compares its name
// exactly, and keyboards capitalize.
func (a *app) setUp() {
	addr, ok := prompt("BoundGate: set up",
		"Address of your organization's control plane, as your administrator gave it\n(for example vpn.example.org, or vpn.example.org:443):", "", true)
	addr = strings.ToLower(strings.TrimSpace(addr))
	if !ok || addr == "" {
		return
	}
	a.run("Setting up", func() error {
		if err := a.client.Configure(ipc.Settings{ControlAddr: addr}); err != nil {
			return err
		}
		for i := 0; i < 30; i++ { // the service starts the node with it
			if s, err := a.client.Status(); err == nil && s.State != "unconfigured" {
				return a.enrollAsking()
			}
			time.Sleep(500 * time.Millisecond)
		}
		return errors.New("the service did not take the address; see its log")
	})
}

// requestAccess enrolls; the first time, the user compares the control
// plane's key with what the administrator gave them, as in boundgatectl.
func (a *app) requestAccess() {
	a.run("Requesting access", a.enrollAsking)
}

func (a *app) enrollAsking() error {
	_, err := a.client.Enroll("", "")
	var unconfirmed *ipc.PinUnconfirmedError
	if !errors.As(err, &unconfirmed) {
		return err
	}
	text := "This device has not talked to this control plane before. It presents the key\n\n" +
		unconfirmed.Fingerprint + "\n\n" +
		"Compare it with the fingerprint your administrator gave you (admin UI, Nodes page). " +
		"If it differs, somebody else is answering at that address.\n\nPin this key and request access?"
	if message("BoundGate: new control plane", text, windows.MB_YESNO|windows.MB_ICONWARNING|windows.MB_DEFBUTTON2) != idYes {
		return nil
	}
	_, err = a.client.Enroll("", unconfirmed.Fingerprint)
	return err
}

func (a *app) copyFingerprint() {
	a.mu.Lock()
	fp := ""
	if a.status != nil {
		fp = a.status.Fingerprint
	}
	a.mu.Unlock()
	if fp == "" {
		return
	}
	if err := setClipboard(fp); err != nil {
		message("Copy fingerprint", err.Error(), windows.MB_ICONERROR)
	}
}

func message(title, text string, flags uint32) int32 {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(title)
	r, _ := windows.MessageBox(0, t, c, flags|windows.MB_TOPMOST|windows.MB_SETFOREGROUND)
	return r
}

func openBrowser(u string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	file, _ := windows.UTF16PtrFromString(u)
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}

const (
	smCXIcon   = 11
	smCXSmIcon = 49
)

// taskbarLight: the taskbar uses the light theme (Settings, Personalization,
// Colors, "Windows mode"), so the icon's glyph is dark.
func taskbarLight() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("SystemUsesLightTheme")
	return err == nil && v == 1
}
