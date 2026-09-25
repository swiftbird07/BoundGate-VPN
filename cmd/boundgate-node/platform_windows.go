//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/ipc"
)

// serviceName is the Windows service; the daemon runs as LocalSystem.
const serviceName = "BoundGate"

var defaults = func() struct{ config, stateDir, profilesDir, logDir string } {
	base := ipc.Dir()
	return struct{ config, stateDir, profilesDir, logDir string }{
		config:      filepath.Join(base, "node.yaml"),
		stateDir:    filepath.Join(base, "state"),
		profilesDir: filepath.Join(base, "profiles"),
		logDir:      filepath.Join(base, "logs"),
	}
}()

// terminateSelf ends the daemon; the service's recovery actions start it again.
func terminateSelf() { os.Exit(1) }

// runMain runs under the service manager when it started us, else in the
// console until Ctrl+C.
func runMain(cfgPath string) error {
	inService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !inService {
		if err := checkDir(ipc.Dir()); err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return run(ctx, cfgPath)
	}
	h := &handler{cfgPath: cfgPath}
	if err := svc.Run(serviceName, h); err != nil {
		return err
	}
	return h.err
}

type handler struct {
	cfgPath string
	err     error
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	// configuration, key and socket come from this directory, and we are SYSTEM
	if err := checkDir(ipc.Dir()); err != nil {
		h.err = err
		logEvent(fmt.Sprintf("boundgate-node does not start: %v", err))
		return true, 2
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, h.cfgPath) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			h.err = err
			if err != nil {
				logEvent(fmt.Sprintf("boundgate-node ended: %v", err))
				// a non-zero exit code makes the recovery actions restart the service
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case h.err = <-done:
				case <-time.After(20 * time.Second):
					h.err = errors.New("did not stop within 20 s")
				}
				return false, 0
			}
		}
	}
}

// logEvent writes to the Application event log: the one place an
// administrator looks when a service does not start (the log files may be
// what failed).
func logEvent(msg string) {
	l, err := eventlog.Open(serviceName)
	if err != nil {
		return
	}
	defer l.Close()
	_ = l.Error(1, msg)
}

// serviceCommand handles `boundgate-node install|uninstall|start|stop`.
func serviceCommand(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "install":
		cfg := ""
		if len(args) == 3 && (args[1] == "-config" || args[1] == "--config") {
			cfg = args[2]
		} else if len(args) != 1 {
			return true, errors.New("usage: boundgate-node install [-config file]")
		}
		return true, install(cfg)
	case "protect":
		// install.ps1, before it writes anything into the directory, and on
		// every update: owner and DACL of the whole tree, or a refusal
		if len(args) != 1 {
			return true, errors.New("usage: boundgate-node protect")
		}
		if err := secureTree(ipc.Dir()); err != nil {
			return true, err
		}
		fmt.Printf("%s: owner Administrators, SYSTEM and Administrators only\n", ipc.Dir())
		return true, nil
	case "uninstall":
		return true, uninstall()
	case "start":
		return true, control(func(s *mgr.Service) error { return s.Start() })
	case "stop":
		return true, control(func(s *mgr.Service) error { _, err := s.Control(svc.Stop); return err })
	}
	return false, nil
}

func install(cfg string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.Abs(exe); err != nil {
		return err
	}
	var args []string
	if cfg != "" {
		if cfg, err = filepath.Abs(cfg); err != nil {
			return err
		}
		args = []string{"-config", cfg}
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager (run as administrator): %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s is already installed (uninstall first)", serviceName)
	}
	// state, keys and logs: SYSTEM and administrators only, nothing inherited,
	// and never in a directory somebody else prepared
	if err := secureTree(ipc.Dir()); err != nil {
		return err
	}
	for _, d := range []string{defaults.stateDir, defaults.profilesDir, defaults.logDir} {
		if err := os.MkdirAll(d, 0o700); err != nil { // inherit the protected DACL
			return err
		}
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  "BoundGate",
		Description:  "BoundGate node: device-bound access to your networks",
		StartType:    mgr.StartAutomatic,
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		ErrorControl: mgr.ErrorNormal,
		// the adapter and routes need the network stack
		Dependencies: []string{"Nsi", "Tcpip"},
	}, args...)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 3600); err != nil {
		return err
	}
	// fails only when an earlier install registered the source already
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	fmt.Printf("installed service %s: %s %v\n", serviceName, exe, args)
	return nil
}

func uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager (run as administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err == nil {
			for i := 0; i < 40; i++ {
				time.Sleep(500 * time.Millisecond)
				if st, err := s.Query(); err != nil || st.State == svc.Stopped {
					break
				}
			}
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	_ = eventlog.Remove(serviceName)
	fmt.Printf("removed service %s; state stays in %s\n", serviceName, ipc.Dir())
	return nil
}

func control(f func(*mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager (run as administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()
	return f(s)
}

// The directory under ProgramData holds the configuration (which names the
// control plane), the device key and the socket, and the service runs as
// SYSTEM. ProgramData lets every user create a directory, and the owner of an
// object may always rewrite its DACL: a standard user who creates
// %ProgramData%\BoundGate before the first install, or plants a file in it,
// would keep control over what SYSTEM reads. So the whole tree belongs to
// Administrators with a protected DACL (SYSTEM and Administrators only), an
// install refuses a tree that anybody else owns, and the service refuses to
// start from a directory that is not protected that way.
const (
	sddlProtectedDir  = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	sddlProtectedFile = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	// NT SERVICE\TrustedInstaller
	trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// trustedOwner: SYSTEM, Administrators, TrustedInstaller.
func trustedOwner(sid *windows.SID) bool {
	return sid != nil && (sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.String() == trustedInstallerSID)
}

// accountName is for messages: DOMAIN\name, or the SID.
func accountName(sid *windows.SID) string {
	if sid == nil {
		return "nobody"
	}
	if a, d, _, err := sid.LookupAccount(""); err == nil {
		if d != "" {
			return d + `\` + a
		}
		return a
	}
	return sid.String()
}

// plainEntry refuses what a planted tree could use to redirect SYSTEM's
// writes: symbolic links, junctions and other reparse points, devices, pipes.
// A socket (the daemon's, left behind) is fine.
func plainEntry(path string) (os.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular|fs.ModeDevice|fs.ModeNamedPipe|fs.ModeCharDevice) != 0 {
		return nil, fmt.Errorf("%s is a link or reparse point (%s): refusing; remove it as administrator", path, fi.Mode().Type())
	}
	return fi, nil
}

func ownerOf(path string) (*windows.SID, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return owner, nil
}

// protect makes Administrators the owner and SYSTEM and Administrators the
// only entries of a protected DACL; directories pass it on to what is created
// in them.
func protect(path string, dir bool) error {
	sddl := sddlProtectedFile
	if dir {
		sddl = sddlProtectedDir
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if owner == nil || dacl == nil { // a nil DACL would be "everyone, everything"
		return errors.New("protect: bad security descriptor")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("protect %s: %w", path, err)
	}
	return nil
}

// walkPlain calls f for every entry below root (not root itself), refusing
// links and reparse points, and never following one.
func walkPlain(root string, f func(path string, fi os.FileInfo) error) error {
	return filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("%s cannot be read completely (%w): refusing", root, err)
		}
		if path == root {
			return nil
		}
		fi, err := plainEntry(path)
		if err != nil {
			return err
		}
		return f(path, fi)
	})
}

// secureTree creates root already protected, or takes over an existing tree
// only if every entry in it belongs to SYSTEM, Administrators or
// TrustedInstaller, and then gives all of it owner Administrators and the
// protected DACL. No fallback: anything else is an error that names the entry.
func secureTree(root string) error {
	sd, err := windows.SecurityDescriptorFromString(sddlProtectedDir)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	switch err := windows.CreateDirectory(p, sa); {
	case err == nil:
		return checkDir(root) // protected from its first moment, and empty
	case !errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		return fmt.Errorf("create %s: %w", root, err)
	}
	refuse := func(path string, owner *windows.SID) error {
		return fmt.Errorf("%s belongs to %s, not to SYSTEM or Administrators: refusing to install into a directory somebody else prepared. "+
			"Look at what is in %s, remove the directory as administrator, and run this again", path, accountName(owner), root)
	}
	fi, err := plainEntry(root)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory: refusing", root)
	}
	owner, err := ownerOf(root)
	if err != nil {
		return err
	}
	if !trustedOwner(owner) {
		return refuse(root, owner)
	}
	// First the directory itself, so that nobody else can add to it while the
	// rest is looked at; then every entry, checked before it is changed.
	if err := protect(root, true); err != nil {
		return err
	}
	if err := walkPlain(root, func(path string, fi os.FileInfo) error {
		owner, err := ownerOf(path)
		if err != nil {
			return err
		}
		if !trustedOwner(owner) {
			return refuse(path, owner)
		}
		return protect(path, fi.IsDir())
	}); err != nil {
		return err
	}
	// what was created through a handle opened before the DACL changed
	if err := walkPlain(root, func(path string, _ os.FileInfo) error {
		owner, err := ownerOf(path)
		if err != nil {
			return err
		}
		if !trustedOwner(owner) {
			return refuse(path, owner)
		}
		return nil
	}); err != nil {
		return err
	}
	return checkDir(root)
}

// checkDir is what the service requires of its directory at every start:
// owned by SYSTEM, Administrators or TrustedInstaller, a protected DACL,
// and access allowed to SYSTEM and Administrators only.
func checkDir(dir string) error {
	fix := "run install.ps1 (or boundgate-node protect) as administrator to set owner and permissions again, after checking what is in it"
	fi, err := plainEntry(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s does not exist: %s", dir, "run install.ps1 as administrator")
		}
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	if !trustedOwner(owner) {
		return fmt.Errorf("%s belongs to %s, not to SYSTEM or Administrators: refusing to run from it; %s", dir, accountName(owner), fix)
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s inherits permissions from %s: refusing to run from it; %s", dir, filepath.Dir(dir), fix)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%s has no DACL (everyone may do everything): refusing to run from it; %s", dir, fix)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("%s: %w", dir, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue // takes rights away
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
				continue
			}
			return fmt.Errorf("%s grants access to %s: refusing to run from it; %s", dir, accountName(sid), fix)
		default:
			return fmt.Errorf("%s has a permission entry of type %d this check does not know: refusing to run from it; %s", dir, ace.Header.AceType, fix)
		}
	}
	return nil
}
