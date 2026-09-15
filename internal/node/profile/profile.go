// Package profile defines routing profiles: which of the networks the hubs
// advertise the user wants routed through the overlay. A profile can only
// narrow what the hubs advertise, never widen it. Which hubs to use is not
// a profile matter: the registry snapshot decides that.
package profile

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode selects how routes are chosen.
type Mode string

const (
	// ModeInclude routes only the listed networks (∩ advertised).
	ModeInclude Mode = "include"
	// ModeFull routes everything the hubs advertise.
	ModeFull Mode = "full"
)

// Profile is one routing intent.
type Profile struct {
	Name    string `yaml:"name"`
	Routing struct {
		Mode     Mode     `yaml:"mode"`
		Networks []string `yaml:"networks"`
	} `yaml:"routing"`

	networks []netip.Prefix
}

// Full is the built-in profile used when none is configured: everything
// the hubs advertise.
func Full() *Profile {
	p := &Profile{Name: "full"}
	p.Routing.Mode = ModeFull
	return p
}

// Load reads and validates one profile file.
func Load(path string) (*Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("profile %s: %w", path, err)
	}
	if p.Name == "" {
		p.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("profile %s: %w", path, err)
	}
	return &p, nil
}

// LoadDir loads every *.yaml / *.yml file in dir, sorted by name. A missing
// directory yields no profiles.
func LoadDir(dir string) ([]*Profile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Profile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		p, err := Load(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (p *Profile) validate() error {
	switch p.Routing.Mode {
	case "":
		p.Routing.Mode = ModeInclude
		fallthrough
	case ModeInclude:
		if len(p.Routing.Networks) == 0 {
			return fmt.Errorf("routing.networks is required for mode include")
		}
	case ModeFull:
	default:
		return fmt.Errorf("unknown routing.mode %q", p.Routing.Mode)
	}
	p.networks = p.networks[:0]
	for _, n := range p.Routing.Networks {
		pfx, err := netip.ParsePrefix(n)
		if err != nil {
			return fmt.Errorf("routing.networks: %w", err)
		}
		p.networks = append(p.networks, pfx.Masked())
	}
	return nil
}

// Networks returns the parsed include list.
func (p *Profile) Networks() []netip.Prefix { return p.networks }

// Effective computes the routes to install: the intersection of what the
// profile wants and what the hubs advertised. For each pair, the more
// specific prefix wins when one contains the other; partially overlapping
// prefixes are ignored. Never returns something outside advertised.
func (p *Profile) Effective(advertised []netip.Prefix) []netip.Prefix {
	if p.Routing.Mode == ModeFull {
		return dedupe(advertised)
	}
	var out []netip.Prefix
	for _, want := range p.networks {
		for _, adv := range advertised {
			switch {
			case adv.Contains(want.Addr()) && adv.Bits() <= want.Bits():
				out = append(out, want) // want ⊆ adv
			case want.Contains(adv.Addr()) && want.Bits() <= adv.Bits():
				out = append(out, adv) // adv ⊆ want
			}
		}
	}
	return dedupe(out)
}

func dedupe(in []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]bool, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		p = p.Masked()
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
