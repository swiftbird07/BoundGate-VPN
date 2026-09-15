package profile

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func pfx(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s))
	for _, x := range s {
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}

func TestEffectiveNeverExceedsAdvertised(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "work.yaml"), []byte(`
routing:
  mode: include
  networks: [10.60.0.0/24, 10.70.0.0/16, 192.168.0.0/16, 172.16.5.0/24]
`), 0o644)
	ps, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := ps[0]
	if p.Name != "work" || p.Routing.Mode != ModeInclude {
		t.Fatalf("%+v", p)
	}
	adv := pfx("10.60.0.0/16", "10.70.1.0/24", "172.16.0.0/12")
	got := p.Effective(adv)
	// 10.60.0.0/24 ⊆ 10.60.0.0/16 -> want; 10.70.1.0/24 ⊆ 10.70.0.0/16 -> adv;
	// 192.168/16 not advertised -> dropped; 172.16.5.0/24 ⊆ 172.16/12 -> want
	want := pfx("10.60.0.0/24", "10.70.1.0/24", "172.16.5.0/24")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for _, g := range got {
		ok := false
		for _, a := range adv {
			if a.Contains(g.Addr()) && a.Bits() <= g.Bits() {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("%v outside advertised", g)
		}
	}
}

func TestFullModeAndValidation(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "full.yml"), []byte("routing:\n  mode: full\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("routing:\n  mode: include\n"), 0o644)
	p, err := Load(filepath.Join(dir, "full.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "full" {
		t.Fatalf("name %q", p.Name)
	}
	if ps, err := LoadDir(filepath.Join(dir, "missing")); err != nil || ps != nil {
		t.Fatalf("missing dir: %v %v", ps, err)
	}
	if got := p.Effective(pfx("10.0.0.0/8", "10.0.0.0/8")); !reflect.DeepEqual(got, pfx("10.0.0.0/8")) {
		t.Fatalf("%v", got)
	}
	if _, err := Load(filepath.Join(dir, "bad.yaml")); err == nil {
		t.Fatal("include without networks accepted")
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("LoadDir ignored invalid profile")
	}
}
