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
		// Exclude is taken out of whatever the mode chose, also out of a
		// larger advertised network that contains it: 0.0.0.0/0 without
		// 10.0.0.0/8 becomes the routes around 10.0.0.0/8.
		Exclude []string `yaml:"exclude"`
	} `yaml:"routing"`

	networks []netip.Prefix
	exclude  []netip.Prefix
}

// Names of the built-in profiles. Every node has them, without a file.
const (
	NameFull    = "full"
	NameLANOnly = "lan-only"
	NameWANOnly = "wan-only"
)

// Private are the networks "LAN only" routes and "WAN only" leaves out:
// the private IPv4 ranges, the shared range (CGNAT, where an overlay pool may
// also live) and IPv6 unique local addresses. Together the two profiles are
// "full", and they never share a route.
var Private = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"}

// Full is the built-in profile used when none is configured: everything
// the hubs advertise.
func Full() *Profile {
	p := &Profile{Name: NameFull}
	p.Routing.Mode = ModeFull
	return p
}

// LANOnly routes the private networks the hubs advertise and leaves the
// internet to this machine's own connection.
func LANOnly() *Profile {
	p := &Profile{Name: NameLANOnly}
	p.Routing.Mode = ModeInclude
	p.Routing.Networks = Private
	must(p.validate())
	return p
}

// WANOnly routes everything the hubs advertise except the private networks:
// the internet through an exit node, the LANs behind the hubs not at all.
func WANOnly() *Profile {
	p := &Profile{Name: NameWANOnly}
	p.Routing.Mode = ModeFull
	p.Routing.Exclude = Private
	must(p.validate())
	return p
}

// Builtin returns the built-in profiles, full first.
func Builtin() []*Profile { return []*Profile{Full(), LANOnly(), WANOnly()} }

func must(err error) {
	if err != nil {
		panic(err)
	}
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
	if p.Routing.Mode == "" && len(p.Routing.Networks) == 0 && len(p.Routing.Exclude) > 0 {
		p.Routing.Mode = ModeFull // "everything but": nothing listed to include
	}
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
	p.exclude = p.exclude[:0]
	for _, n := range p.Routing.Exclude {
		pfx, err := netip.ParsePrefix(n)
		if err != nil {
			return fmt.Errorf("routing.exclude: %w", err)
		}
		p.exclude = append(p.exclude, pfx.Masked())
	}
	return nil
}

// Networks returns the parsed include list.
func (p *Profile) Networks() []netip.Prefix { return p.networks }

// Effective computes the routes to install: the intersection of what the
// profile wants and what the hubs advertised, without what it excludes. For
// each pair, the more specific prefix wins when one contains the other;
// partially overlapping prefixes are ignored. Never returns something
// outside advertised.
func (p *Profile) Effective(advertised []netip.Prefix) []netip.Prefix {
	return p.EffectiveExcept(advertised, nil)
}

// EffectiveExcept is Effective with extra networks taken out as if the
// profile excluded them: what a node announces itself it reaches on its own,
// never through a hub, and a broader advertised network is replaced by the
// routes around it. A default route among extra is ignored — it would leave
// nothing, and an exit node announcing one says nothing about the networks it
// reaches by itself.
func (p *Profile) EffectiveExcept(advertised, extra []netip.Prefix) []netip.Prefix {
	exclude := p.exclude
	if len(extra) > 0 {
		exclude = make([]netip.Prefix, 0, len(p.exclude)+len(extra))
		exclude = append(exclude, p.exclude...)
		for _, e := range extra {
			if e.Bits() > 0 {
				exclude = append(exclude, e.Masked())
			}
		}
	}
	return dedupe(subtract(p.chosen(advertised), exclude))
}

func (p *Profile) chosen(advertised []netip.Prefix) []netip.Prefix {
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

// subtract takes every excluded network out of in. A prefix inside an
// excluded one goes; a prefix that contains one is replaced by the prefixes
// that cover it except that network (halving until the halves no longer
// overlap it).
func subtract(in, exclude []netip.Prefix) []netip.Prefix {
	out := in
	for _, e := range exclude {
		var next []netip.Prefix
		for _, p := range out {
			next = append(next, without(p.Masked(), e)...)
		}
		out = next
	}
	return out
}

func without(p, e netip.Prefix) []netip.Prefix {
	switch {
	case p.Addr().Is4() != e.Addr().Is4():
		return []netip.Prefix{p}
	case e.Bits() <= p.Bits() && e.Contains(p.Addr()):
		return nil // e covers p
	case !(p.Bits() < e.Bits() && p.Contains(e.Addr())):
		return []netip.Prefix{p} // disjoint
	}
	lo, hi := halves(p)
	return append(without(lo, e), without(hi, e)...)
}

// halves splits p into its two prefixes one bit longer.
func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits()
	a := p.Addr().As16()
	off := 0
	if p.Addr().Is4() {
		off = 96 // the IPv4 bits sit at the end of the 16 bytes
	}
	i := off + bits
	a[i/8] |= 0x80 >> (i % 8)
	hi := netip.AddrFrom16(a)
	if p.Addr().Is4() {
		hi = hi.Unmap()
	}
	return netip.PrefixFrom(p.Addr(), bits+1), netip.PrefixFrom(hi, bits+1)
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
