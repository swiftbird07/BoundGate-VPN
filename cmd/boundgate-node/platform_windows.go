//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

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
	for _, d := range []string{ipc.Dir(), defaults.stateDir, defaults.profilesDir, defaults.logDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	// state, keys and logs: SYSTEM and administrators only, nothing inherited
	if err := protectDir(ipc.Dir()); err != nil {
		return err
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

// protectDir gives SYSTEM and Administrators full control and removes
// everything inherited (ProgramData lets every user read by default).
func protectDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
