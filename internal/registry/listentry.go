package registry

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// AddrEntry is the address form of a list entry: a single address, a CIDR
// prefix or a range, with an optional port or port range. A dynamic access
// list holds these next to names, so one list can say "these names, and
// besides them this printer and this port of that server".
//
//	10.60.0.10            a single address
//	10.60.0.0/24          a prefix
//	10.60.0.10-10.60.0.20 a range
//	10.60.0.10:443        one port of it
//	10.60.0.0/24:8000-8100 a port range
//	[2001:db8::1]:443     IPv6 with a port needs brackets
type AddrEntry struct {
	Lo, Hi       netip.Addr
	Port, PortTo uint16 // 0: any port
}

// Matches reports whether a destination falls into the entry.
func (e AddrEntry) Matches(a netip.Addr, port uint16) bool {
	a = a.Unmap()
	if !a.IsValid() || a.Is4() != e.Lo.Is4() {
		return false
	}
	if a.Compare(e.Lo) < 0 || a.Compare(e.Hi) > 0 {
		return false
	}
	return e.Port == 0 || (port >= e.Port && port <= e.PortTo)
}

// String is the canonical text of the entry, the form it is stored in.
func (e AddrEntry) String() string {
	addr := e.Lo.String()
	switch {
	case e.Lo == e.Hi:
	case prefixOf(e.Lo, e.Hi) != "":
		addr = prefixOf(e.Lo, e.Hi)
	default:
		addr += "-" + e.Hi.String()
	}
	if e.Port == 0 {
		return addr
	}
	if e.Lo.Is6() {
		addr = "[" + addr + "]"
	}
	if e.Port == e.PortTo {
		return addr + ":" + strconv.Itoa(int(e.Port))
	}
	return fmt.Sprintf("%s:%d-%d", addr, e.Port, e.PortTo)
}

// ParseAddrEntry reads the address form of a list entry. Anything that is
// not an address (a name) yields ok=false without an error; an address with
// a broken port or range yields the error, so that a typo is not silently
// kept as a host name.
func ParseAddrEntry(s string) (AddrEntry, bool, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return AddrEntry{}, false, nil
	}
	addr, ports := s, ""
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return AddrEntry{}, false, errors.New("missing ]")
		}
		addr = s[1:end]
		switch rest := s[end+1:]; {
		case rest == "":
		case strings.HasPrefix(rest, ":"):
			ports = rest[1:]
		default:
			return AddrEntry{}, false, fmt.Errorf("trailing %q", rest)
		}
	} else if i := strings.LastIndexByte(s, ':'); i >= 0 && !strings.Contains(s[:i], ":") {
		addr, ports = s[:i], s[i+1:]
	}
	e, ok := parseRange(addr)
	if !ok {
		if ports != "" {
			return AddrEntry{}, false, fmt.Errorf("%q: a port belongs to an address, not to a name", s)
		}
		return AddrEntry{}, false, nil // a name; the caller checks it
	}
	if ports == "" {
		return e, true, nil
	}
	lo, hi, err := parsePorts(ports)
	if err != nil {
		return AddrEntry{}, false, err
	}
	e.Port, e.PortTo = lo, hi
	return e, true, nil
}

// parseRange reads the address part: a-b, a/len or a.
func parseRange(s string) (AddrEntry, bool) {
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		a, err1 := netip.ParseAddr(lo)
		b, err2 := netip.ParseAddr(hi)
		if err1 != nil || err2 != nil {
			return AddrEntry{}, false
		}
		a, b = a.Unmap(), b.Unmap()
		if a.Is4() != b.Is4() || a.Compare(b) > 0 {
			return AddrEntry{}, false
		}
		return AddrEntry{Lo: a, Hi: b}, true
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Is4In6() {
			return AddrEntry{}, false // ::ffff:10.0.0.0/104 and the like: write it as IPv4
		}
		p = p.Masked()
		return AddrEntry{Lo: p.Addr(), Hi: lastOf(p)}, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return AddrEntry{Lo: a, Hi: a}, true
	}
	return AddrEntry{}, false
}

func parsePorts(s string) (uint16, uint16, error) {
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		hi = lo
	}
	a, err1 := strconv.Atoi(lo)
	b, err2 := strconv.Atoi(hi)
	if err1 != nil || err2 != nil || a < 1 || b < 1 || a > 65535 || b > 65535 || a > b {
		return 0, 0, fmt.Errorf("port %q: 1-65535, or a range like 8000-8100", s)
	}
	return uint16(a), uint16(b), nil
}

// lastOf is the highest address of a prefix.
func lastOf(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// prefixOf names the range as a CIDR prefix when it is one.
func prefixOf(lo, hi netip.Addr) string {
	for bits := 0; bits <= lo.BitLen(); bits++ {
		p := netip.PrefixFrom(lo, bits)
		if p.Masked().Addr() == lo && lastOf(p) == hi {
			return p.String()
		}
	}
	return ""
}
