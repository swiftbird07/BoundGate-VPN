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
	"os"
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
	// the route picker: the profiles of the network that runs plus the
	// built-ins of every other network it belongs to (docs/NETWORKS.md)
	maxProfiles = 16
	maxDetails  = 20
	idYes       = 6 // MessageBox answer
)

func main() {
	socket := flag.String("socket", ipc.DefaultSocket(), "the service's socket")
	render := flag.String("render-panel", "", "write the panel in every phase as PNG files into this directory, and exit")
	flag.Parse()
	if *render != "" {
		// No window in this mode, so no message box either: a modal dialog
		// nobody can click is what a script or an ssh session hangs on.
		// The redirected error stream is where this belongs.
		if err := renderPanels(*render); err != nil {
			fmt.Fprintln(os.Stderr, "render-panel:", err)
			os.Exit(1)
		}
		return
	}
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
	panel  *panelWin

	title, detail                        *systray.MenuItem
	connect, disconnect, signIn, signOut *systray.MenuItem
	enroll, setup, profileMenu           *systray.MenuItem
	addNet                               *systray.MenuItem
	details, copyFP, repair              *systray.MenuItem
	profiles                             [maxProfiles]*systray.MenuItem
	detailLines                          [maxDetails]*systray.MenuItem

	mu        sync.Mutex
	busy      string // the action in flight
	waiting   bool   // a sign-in is open in the browser; the buttons stay alive
	actionErr string // the last action's failure, shown in the panel
	status    *node.Status
	names     []string
	nets      ipc.NetworkList
	// routes is the picker as the menu shows it, in the order of the items
	routes    []tray.RouteChoice
	last      tray.Reading
	lastPhase tray.Phase
	phaseSeen bool
	lastHint  time.Time // Status.SignIn.At last asked about

	// draw serializes refresh: the poll and the end of an action both redraw
	draw      sync.Mutex
	lastColor tray.Color
	lastLight bool
	iconSet   bool
}

func (a *app) ready() {
	systray.SetTitle("BoundGate")
	// a click on the icon opens the panel; the right button keeps the menu
	a.panel = newPanel(a.dispatch)
	systray.SetOnTapped(a.panel.toggle)
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
	a.addNet = systray.AddMenuItem("Add network…", "Another mesh this PC belongs to; it gets a device key of its own")
	a.enroll = systray.AddMenuItem("Request access…", "Enroll this device with the control plane")
	a.profileMenu = systray.AddMenuItem("Profile", "Which networks go through BoundGate")
	for i := range a.profiles {
		a.profiles[i] = a.profileMenu.AddSubMenuItemCheckbox("", "", false)
		a.profiles[i].Hide()
		go a.onClick(a.profiles[i].ClickedCh, func() { a.pickRoute(i) })
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
	a.repair = systray.AddMenuItem("Repair network…", "Give this PC its resolver and routes back after a run that ended badly")
	quit := systray.AddMenuItem("Quit BoundGate tray", "The service keeps running; the tunnel stays as it is")

	go a.onClick(a.connect.ClickedCh, func() { a.up("") })
	go a.onClick(a.disconnect.ClickedCh, func() { a.run("Disconnecting", func() error { _, err := a.client.Down(); return err }) })
	go a.onClick(a.signIn.ClickedCh, a.login)
	go a.onClick(a.signOut.ClickedCh, func() { a.run("Signing out", func() error { _, err := a.client.Logout(); return err }) })
	go a.onClick(a.enroll.ClickedCh, a.requestAccess)
	go a.onClick(a.setup.ClickedCh, a.setUp)
	go a.onClick(a.addNet.ClickedCh, a.addNetwork)
	go a.onClick(a.copyFP.ClickedCh, a.copyFingerprint)
	go a.onClick(a.repair.ClickedCh, a.repairNetwork)
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
	var nets ipc.NetworkList
	if st != nil && st.Enrollment == "approved" {
		names, _ = a.client.Profiles()
	}
	if st != nil {
		// a daemon that holds one network answers with that one; an older
		// one does not know the endpoint, and the picker stays as it was
		nets, _ = a.client.Networks()
	}
	now := tray.ReadingOf(st, time.Now())

	a.mu.Lock()
	rate := tray.RateOf(a.last, now)
	a.last, a.status, a.names, a.nets = now, st, names, nets
	a.routes = tray.RouteChoices(st, names, nets)
	routes := a.routes
	busy, waiting, actionErr := a.busy, a.waiting, a.actionErr
	phase := tray.PhaseOf(st, err)
	askSignIn := a.phaseSeen && phase == tray.LoginRequired && a.lastPhase != tray.LoginRequired && busy == "" && !waiting
	a.lastPhase, a.phaseSeen = phase, true
	// a node refused a connection that a signed-in user would be let
	// through (Status.SignIn, only while nobody is signed in): once per refusal
	var hint string
	if st != nil && st.SignIn != nil && !st.SignIn.At.Equal(a.lastHint) && busy == "" && !waiting {
		a.lastHint = st.SignIn.At
		hint = tray.SignInHintText(st.SignIn)
	}
	a.mu.Unlock()
	if askSignIn {
		// the session ended (24 h by default) while nobody looked at the
		// tray: a message box is what a tray app has for a notification
		go func() {
			if message("BoundGate", "Your BoundGate session has ended. Sign in again now?", windows.MB_YESNO|windows.MB_ICONINFORMATION) == idYes {
				a.login()
			}
		}()
	} else if hint != "" {
		go func() {
			if message("BoundGate", hint+"\n\nSign in now?", windows.MB_YESNO|windows.MB_ICONINFORMATION) == idYes {
				a.login()
			}
		}()
	}
	a.panel.update(tray.PanelInput{Status: st, Err: err, Busy: busy, Waiting: waiting, Profiles: names, Networks: nets, Rate: rate, ActionError: actionErr})

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
	show(a.signIn, v.CanLogin, idle && !waiting)
	show(a.signOut, v.CanLogout, idle)
	show(a.enroll, v.CanEnroll, idle)
	show(a.setup, v.CanSetup, idle)
	// another network is for a PC a person uses; a daemon whose control
	// plane stands in its configuration file says so instead
	show(a.addNet, st != nil && nets.Single == "" && !v.CanSetup, idle)

	// one picker: the profiles of this network, and with several networks
	// the other networks' as well ("Work · Full")
	a.profileMenu.SetTitle("Route")
	if len(nets.Networks) > 1 {
		a.profileMenu.SetTitle("Network")
	}
	show(a.profileMenu, len(routes) > 1, idle)
	for i, it := range a.profiles {
		if i >= len(routes) {
			it.Hide()
			continue
		}
		it.SetTitle(routes[i].Title)
		if routes[i].On {
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
		a.busy, a.actionErr = "", ""
		if err != nil {
			a.actionErr = label + ": " + err.Error()
		}
		a.mu.Unlock()
		a.refresh()
		// the open panel shows the failure; otherwise a message box does
		if err != nil && !a.panel.isOpen() {
			message(label, err.Error(), windows.MB_ICONERROR)
		}
	}()
}

// dispatch runs what the panel's buttons name.
func (a *app) dispatch(act string) {
	switch {
	case act == tray.ActConnect:
		a.up("")
	case act == tray.ActDisconnect:
		a.run("Disconnecting", func() error { _, err := a.client.Down(); return err })
	case act == tray.ActSignIn:
		a.login()
	case act == tray.ActSignOut:
		a.run("Signing out", func() error { _, err := a.client.Logout(); return err })
	case act == tray.ActRepair:
		a.repairNetwork()
	case act == tray.ActSetUp:
		a.setUp()
	case act == tray.ActEnroll:
		a.requestAccess()
	case act == tray.ActCopyFP:
		a.copyFingerprint()
	case act == tray.ActQuit:
		systray.Quit()
	case strings.HasPrefix(act, tray.ActProfile), strings.HasPrefix(act, tray.ActNetwork):
		a.mu.Lock()
		routes := a.routes
		a.mu.Unlock()
		for i, c := range routes {
			if c.Action() == act {
				a.pickRoute(i)
				return
			}
		}
	}
}

func (a *app) up(profile string) {
	a.run("Connecting", func() error { _, err := a.client.Up(profile); return err })
}

// pickRoute is the i-th entry of the route picker: a profile of this
// network, or a profile of another one.
func (a *app) pickRoute(i int) {
	a.mu.Lock()
	var c tray.RouteChoice
	if i < len(a.routes) {
		c = a.routes[i]
	}
	a.mu.Unlock()
	switch {
	case c.Profile == "" || c.On:
		return
	case c.Network == "":
		// The routes follow the profile; the tunnel stays. Taking the overlay
		// down and up for it dropped every connection through it.
		a.run("Switching to "+c.Label, func() error {
			_, err := a.client.SetProfile(c.Profile)
			return err
		})
	default:
		// another mesh: the daemon takes this network down, which takes its
		// routes with it, and comes up in the other one (R143)
		a.run("Switching to "+c.NetworkLabel, func() error {
			_, _ = a.client.Down()
			if err := a.client.SelectNetwork(c.Network, c.Profile); err != nil {
				return err
			}
			// the daemon restarts its socket with the other network
			for i := 0; i < 40; i++ {
				time.Sleep(500 * time.Millisecond)
				if st, err := a.client.Status(); err == nil && (st.NetworkID == c.Network || st.State == ipc.StateUnconfigured) {
					return nil
				}
			}
			return nil
		})
	}
}

// login opens the control plane's sign-in page in the browser and waits for
// the result, like `boundgatectl login`.
func (a *app) login() {
	a.mu.Lock()
	waiting := a.waiting
	a.mu.Unlock()
	if waiting { // one browser window is enough
		return
	}
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
		// The browser is open; the rest is the user's time and must not hold
		// the one-action lock -- somebody who decides against signing in has
		// to be able to disconnect instead.
		go a.awaitLogin(start.FlowID)
		return nil
	})
}

// awaitLogin follows the sign-in flow while the user is in the browser. It
// shows in the panel ("Signing in…", Waiting) but leaves every button alive,
// and it gives up as soon as the user has taken the tunnel down instead.
func (a *app) awaitLogin(flow string) {
	a.mu.Lock()
	a.waiting = true
	a.mu.Unlock()
	var fail string
	defer func() {
		a.mu.Lock()
		a.waiting = false
		if fail != "" {
			a.actionErr = "Signing in: " + fail
		}
		a.mu.Unlock()
		a.refresh()
	}()
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		st, err := a.client.LoginWait(flow, 25*time.Second)
		if err != nil {
			fail = err.Error()
			return
		}
		switch st.Status {
		case "pending":
			// the user may have disconnected meanwhile: then the flow is
			// nobody's business any more
			if s, err := a.client.Status(); err == nil && s.State == node.StateDown {
				return
			}
			continue
		case "failed":
			fail = "the sign-in failed"
			if st.Error != "" {
				fail = st.Error
			}
			return
		}
		a.refresh()
		return
	}
	fail = "the sign-in took too long"
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

// addNetwork asks for another mesh and switches to it: a device key of its
// own, so it enrolls and is approved there on its own (docs/NETWORKS.md).
func (a *app) addNetwork() {
	addr, ok := prompt("BoundGate: add a network",
		"Address of the other network's control plane (for example vpn.corp.example).\nThis PC gets a device key of its own there and has to be approved there:", "", true)
	addr = strings.ToLower(strings.TrimSpace(addr))
	if !ok || addr == "" {
		return
	}
	name, _ := prompt("BoundGate: add a network", "What to call it (for example Work). Empty: its address.", "", false)
	name = strings.TrimSpace(name)
	label := name
	if label == "" {
		label = addr
	}
	a.run("Adding "+label, func() error {
		_, _ = a.client.Down()
		n, err := a.client.AddNetwork(ipc.NewNetwork{Name: name, ControlAddr: addr, Select: true})
		if err != nil {
			return err
		}
		for i := 0; i < 40; i++ { // the service comes back in the new network
			time.Sleep(500 * time.Millisecond)
			if st, err := a.client.Status(); err == nil && (st.NetworkID == n.ID || st.State == ipc.StateUnconfigured) {
				return a.enrollAsking()
			}
		}
		return errors.New("the service did not switch to the new network; see its log")
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

// repairNetwork is the way back for whoever is looking at a PC that resolves
// no names any more: the service takes back what a run that is gone left on
// this machine -- the policy rule for "." above all, which outlives a reboot
// -- and applies again what a running node should have (R144). It says what
// it did, because "nothing to repair" is an answer too. Without a service
// there is still `boundgate-node -repair` in a shell.
func (a *app) repairNetwork() {
	a.run("Repairing", func() error {
		rep, err := a.client.Repair()
		if err != nil {
			return err
		}
		text := rep.Summary
		for _, k := range rep.LeftAlone {
			text += "\n\nLeft alone, its tunnel device is still there:\n" + k
		}
		message("Repair network", text, windows.MB_ICONINFORMATION)
		return nil
	})
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
