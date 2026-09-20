package update

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
)

// Where releases of this distribution are published: the public mirror, which
// anyone can read (docs/RELEASES.md). The Gitea instance the project lives on
// wants a login.
const (
	DefaultKind = KindGitHub
	DefaultRepo = "swiftbird07/BoundGate-VPN"
)

// Status is what the daemon tells the app and the CLI about updates.
type Status struct {
	Current   string    `json:"current"`
	Latest    string    `json:"latest,omitempty"`
	Available bool      `json:"available"`
	CheckedAt time.Time `json:"checked_at,omitzero"`
	Error     string    `json:"error,omitempty"`
	PageURL   string    `json:"page_url,omitempty"`
	// CanInstall: this daemon can install the update itself (it runs from an
	// app bundle); otherwise InstallHint says how it is done.
	CanInstall  bool   `json:"can_install"`
	InstallHint string `json:"install_hint,omitempty"`
	Installing  bool   `json:"installing,omitempty"`
}

// Service checks for releases in the background and installs one on request.
type Service struct {
	Source    Source
	TokenFile string // read at every check, so a rotated token needs no restart
	Keys      binding.Signers
	Current   string
	Interval  time.Duration
	// Bundle is the app this daemon runs from, "" when it does not.
	Bundle string
	// Idle reports whether the node is down; an update is only installed then.
	Idle    func() bool
	WorkDir string
	Mac     MacApp
	Log     *slog.Logger

	mu     sync.Mutex
	status Status
	apply  sync.Mutex
}

// Status returns the result of the last check.
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status
	st.Current = s.Current
	st.CanInstall = s.Bundle != ""
	if !st.CanInstall {
		st.InstallHint = "this node does not run from the app bundle; update it the way it was installed (deploy/prod/update.sh, your package)"
	}
	return st
}

func (s *Service) source() Source {
	src := s.Source
	if s.TokenFile != "" {
		if b, err := os.ReadFile(s.TokenFile); err == nil {
			src.Token = strings.TrimSpace(string(b))
		}
	}
	return src
}

// Check asks the release source now.
func (s *Service) Check(ctx context.Context) Status {
	_, st := s.check(ctx)
	return st
}

func (s *Service) check(ctx context.Context) (*Release, Status) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	r, err := s.source().Latest(ctx, s.Keys)
	s.mu.Lock()
	s.status.CheckedAt = time.Now().UTC()
	if err != nil {
		s.status.Error = err.Error()
	} else {
		s.status.Error = ""
		s.status.Latest = r.Manifest.Version
		s.status.PageURL = r.PageURL
		s.status.Available = Newer(s.Current, r.Manifest.Version)
	}
	s.mu.Unlock()
	return r, s.Status()
}

// Run checks shortly after start and then every Interval (with some jitter,
// so a fleet does not arrive at the server together).
func (s *Service) Run(ctx context.Context) {
	if s.Interval <= 0 {
		return
	}
	wait := 2*time.Minute + rand.N(3*time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if st := s.Check(ctx); st.Error != "" {
			s.Log.Warn("update check", "err", st.Error)
		} else if st.Available {
			s.Log.Info("update available", "current", st.Current, "latest", st.Latest)
		}
		wait = s.Interval + rand.N(s.Interval/10+time.Second)
	}
}

// Apply installs the latest release over the running app. It verifies the
// release again from scratch - nothing from an earlier check is reused - and
// installs only a release that is newer than this build.
func (s *Service) Apply(ctx context.Context) error {
	if !s.apply.TryLock() {
		return errors.New("update: an installation is already running")
	}
	defer s.apply.Unlock()
	if s.Bundle == "" {
		return errors.New("update: " + s.Status().InstallHint)
	}
	if s.Idle != nil && !s.Idle() {
		return errors.New("update: disconnect first")
	}
	s.setInstalling(true)
	defer s.setInstalling(false)
	r, st := s.check(ctx)
	if st.Error != "" {
		return errors.New(st.Error)
	}
	if !st.Available {
		return fmt.Errorf("update: %s is the latest release", s.Current)
	}
	a, ok := r.Manifest.Find("app", runtime.GOOS, runtime.GOARCH)
	if !ok {
		return fmt.Errorf("update: release %s has no app for %s/%s", r.Manifest.Version, runtime.GOOS, runtime.GOARCH)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	os.RemoveAll(s.WorkDir)
	defer os.RemoveAll(s.WorkDir)
	zip, err := s.source().Download(ctx, r, a, s.WorkDir)
	if err != nil {
		return err
	}
	if err := s.Mac.Install(ctx, zip, s.Bundle); err != nil {
		return err
	}
	s.Log.Warn("update installed; the daemon restarts from the new app", "from", s.Current, "to", r.Manifest.Version)
	return nil
}

func (s *Service) setInstalling(v bool) {
	s.mu.Lock()
	s.status.Installing = v
	s.mu.Unlock()
}
