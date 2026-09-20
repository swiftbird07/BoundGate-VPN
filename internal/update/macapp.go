package update

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// MacApp installs a downloaded BoundGate.app over the running one. It runs in
// the root daemon, so replacing the bundle needs no administrator prompt. The
// zip has already been checked against the signed manifest; on top of that
// the bundle must carry a valid Apple code signature of the same team as the
// one it replaces and pass Gatekeeper (notarization), and it must be the same
// app. A development build (ad hoc signed) has no team to compare with; there
// the signed manifest alone decides.
type MacApp struct {
	// Run executes a system tool and returns its combined output.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// SystemRun runs the tool with nothing of the daemon's environment.
func SystemRun(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	return cmd.CombinedOutput()
}

// BundleOf returns the .app that contains an executable in Contents/MacOS.
func BundleOf(exe string) (string, bool) {
	macos := filepath.Dir(exe)
	contents := filepath.Dir(macos)
	bundle := filepath.Dir(contents)
	if filepath.Base(macos) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.HasSuffix(bundle, ".app") {
		return "", false
	}
	return bundle, true
}

var teamRE = regexp.MustCompile(`(?m)^TeamIdentifier=(.+)$`)

func (m MacApp) team(ctx context.Context, bundle string) (string, error) {
	out, err := m.Run(ctx, "/usr/bin/codesign", "-dv", "--verbose=2", bundle)
	if err != nil {
		return "", fmt.Errorf("codesign -d %s: %v: %s", bundle, err, firstLine(out))
	}
	match := teamRE.FindSubmatch(out)
	if match == nil || string(match[1]) == "not set" {
		return "", nil
	}
	team := string(match[1])
	if !regexp.MustCompile(`^[A-Z0-9]{10}$`).MatchString(team) {
		return "", fmt.Errorf("unexpected team identifier %q", team)
	}
	return team, nil
}

func (m MacApp) bundleID(ctx context.Context, bundle string) (string, error) {
	out, err := m.Run(ctx, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleIdentifier", filepath.Join(bundle, "Contents", "Info.plist"))
	if err != nil {
		return "", fmt.Errorf("Info.plist of %s: %v", bundle, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// Install unpacks zipPath and puts the app it contains in the place of
// bundle. Nothing of the running app is touched before every check passed,
// and a failed swap is undone.
func (m MacApp) Install(ctx context.Context, zipPath, bundle string) error {
	parent, name := filepath.Dir(bundle), filepath.Base(bundle)
	// next to the bundle: the swap must be a rename on one volume
	stage, err := os.MkdirTemp(parent, ".boundgate-update-")
	if err != nil {
		return fmt.Errorf("update: staging next to %s: %w", bundle, err)
	}
	defer os.RemoveAll(stage)
	if out, err := m.Run(ctx, "/usr/bin/ditto", "-x", "-k", zipPath, stage); err != nil {
		return fmt.Errorf("update: unpack: %v: %s", err, firstLine(out))
	}
	fresh := filepath.Join(stage, name)
	if fi, err := os.Lstat(fresh); err != nil || !fi.IsDir() {
		return fmt.Errorf("update: the download does not contain %s", name)
	}

	oldID, err := m.bundleID(ctx, bundle)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	newID, err := m.bundleID(ctx, fresh)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if oldID == "" || oldID != newID {
		return fmt.Errorf("update: the download is another app (%q, this is %q)", newID, oldID)
	}
	if out, err := m.Run(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", fresh); err != nil {
		return fmt.Errorf("update: the code signature of the download is not valid: %s", firstLine(out))
	}
	team, err := m.team(ctx, bundle)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if team != "" {
		req := fmt.Sprintf(`anchor apple generic and certificate leaf[subject.OU] = "%s"`, team)
		if out, err := m.Run(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", "-R="+req, fresh); err != nil {
			return fmt.Errorf("update: the download is not signed by this app's developer (team %s): %s", team, firstLine(out))
		}
		if out, err := m.Run(ctx, "/usr/sbin/spctl", "--assess", "--type", "execute", fresh); err != nil {
			return fmt.Errorf("update: Gatekeeper does not accept the download (not notarized?): %s", firstLine(out))
		}
	}

	old := filepath.Join(parent, fmt.Sprintf(".%s.replaced-%d", name, time.Now().Unix()))
	if err := os.Rename(bundle, old); err != nil {
		return fmt.Errorf("update: move the current app aside: %w", err)
	}
	if err := os.Rename(fresh, bundle); err != nil {
		if back := os.Rename(old, bundle); back != nil {
			return fmt.Errorf("update: install failed (%v) and the previous app could not be restored (%v); it is at %s", err, back, old)
		}
		return fmt.Errorf("update: install: %w", err)
	}
	_ = os.RemoveAll(old) // installed; a leftover is hidden and harmless
	return nil
}
