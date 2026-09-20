package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeMac plays ditto, PlistBuddy, codesign and spctl. The "zip" is a text
// file: line 1 the bundle id of the app inside, line 2 its team ("" = ad hoc),
// then flags: badsig, unnotarized, noapp.
type fakeMac struct {
	teams map[string]string // bundle path -> team, for installed apps
	calls []string
}

func (f *fakeMac) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, filepath.Base(name)+" "+strings.Join(args, " "))
	read := func(bundle, file string) string {
		b, _ := os.ReadFile(filepath.Join(bundle, "Contents", file))
		return strings.TrimSpace(string(b))
	}
	switch filepath.Base(name) {
	case "ditto":
		zip, _ := os.ReadFile(args[2])
		lines := strings.Split(string(zip), "\n")
		if strings.Contains(string(zip), "noapp") {
			return nil, nil
		}
		app := filepath.Join(args[3], "BoundGate.app", "Contents")
		os.MkdirAll(filepath.Join(app, "MacOS"), 0o755)
		os.WriteFile(filepath.Join(app, "Info.plist"), []byte(lines[0]), 0o644)
		os.WriteFile(filepath.Join(app, "team"), []byte(lines[1]), 0o644)
		os.WriteFile(filepath.Join(app, "flags"), []byte(strings.Join(lines[2:], " ")), 0o644)
		os.WriteFile(filepath.Join(app, "MacOS", "boundgate-node"), []byte("new"), 0o755)
		return nil, nil
	case "PlistBuddy":
		return []byte(read(filepath.Dir(filepath.Dir(args[2])), "Info.plist") + "\n"), nil
	case "codesign":
		bundle := args[len(args)-1]
		if args[0] == "-dv" {
			team := read(bundle, "team")
			if team == "" {
				team = "not set"
			}
			return []byte("Identifier=x\nTeamIdentifier=" + team + "\nSealed Resources=none\n"), nil
		}
		if strings.Contains(read(bundle, "flags"), "badsig") {
			return []byte("a sealed resource is missing or invalid"), errors.New("exit 1")
		}
		for _, a := range args {
			if strings.HasPrefix(a, "-R=") && !strings.Contains(a, `"`+read(bundle, "team")+`"`) {
				return []byte("test-requirement: code failed to satisfy specified code requirement(s)"), errors.New("exit 3")
			}
		}
		return nil, nil
	case "spctl":
		if strings.Contains(read(args[len(args)-1], "flags"), "unnotarized") {
			return []byte("rejected"), errors.New("exit 3")
		}
		return []byte("accepted"), nil
	}
	return nil, errors.New("unexpected tool " + name)
}

func installed(t *testing.T, id, team string) string {
	t.Helper()
	bundle := filepath.Join(t.TempDir(), "BoundGate.app")
	c := filepath.Join(bundle, "Contents")
	os.MkdirAll(filepath.Join(c, "MacOS"), 0o755)
	os.WriteFile(filepath.Join(c, "Info.plist"), []byte(id), 0o644)
	os.WriteFile(filepath.Join(c, "team"), []byte(team), 0o644)
	os.WriteFile(filepath.Join(c, "MacOS", "boundgate-node"), []byte("old"), 0o755)
	return bundle
}

func TestMacAppInstall(t *testing.T) {
	const id, team = "de.swiftbird.boundgate", "ABCDE12345"
	for _, c := range []struct {
		name, curTeam, zip string
		wantErr            string
	}{
		{"same developer, notarized", team, id + "\n" + team, ""},
		{"development build: the manifest alone decides", "", id + "\n", ""},
		{"another app", team, "com.evil.app\n" + team, "another app"},
		{"broken signature", team, id + "\n" + team + "\nbadsig", "code signature"},
		{"another developer", team, id + "\nZZZZZ99999", "not signed by this app's developer"},
		{"ad hoc download over a signed app", team, id + "\n", "not signed by this app's developer"},
		{"not notarized", team, id + "\n" + team + "\nunnotarized", "Gatekeeper"},
		{"no app inside", team, id + "\n" + team + "\nnoapp", "does not contain"},
	} {
		bundle := installed(t, id, c.curTeam)
		zip := filepath.Join(t.TempDir(), "app.zip")
		os.WriteFile(zip, []byte(c.zip), 0o600)
		f := &fakeMac{}
		err := MacApp{Run: f.run}.Install(context.Background(), zip, bundle)
		got, _ := os.ReadFile(filepath.Join(bundle, "Contents", "MacOS", "boundgate-node"))
		if c.wantErr == "" {
			if err != nil || string(got) != "new" {
				t.Errorf("%s: err %v, binary %q", c.name, err, got)
			}
		} else if err == nil || !strings.Contains(err.Error(), c.wantErr) || string(got) != "old" {
			t.Errorf("%s: err %v, binary %q (the running app must stay untouched)", c.name, err, got)
		}
		if left, _ := os.ReadDir(filepath.Dir(bundle)); len(left) != 1 {
			t.Errorf("%s: leftovers next to the app: %v", c.name, left)
		}
	}
}

func TestBundleOf(t *testing.T) {
	if b, ok := BundleOf("/Applications/BoundGate.app/Contents/MacOS/boundgate-node"); !ok || b != "/Applications/BoundGate.app" {
		t.Fatalf("%q %v", b, ok)
	}
	for _, exe := range []string{"/usr/local/bin/boundgate-node", "/Applications/BoundGate.app/Contents/Resources/boundgate-node", "/x/MacOS/boundgate-node"} {
		if _, ok := BundleOf(exe); ok {
			t.Errorf("%s taken for a bundle", exe)
		}
	}
}
