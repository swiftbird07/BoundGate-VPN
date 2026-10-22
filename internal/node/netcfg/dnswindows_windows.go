//go:build windows

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ErrNoResolver says Windows did not take the resolver setting. The node
// keeps the machine's own resolver and reports it; it is not a reason to
// refuse the overlay.
var ErrNoResolver = errors.New("netcfg: the name resolution policy did not take the resolver")

// SetLinkDNS implements LinkDNSConfigurator: while the overlay is up this
// machine asks the hub's resolvers for every name, and when it goes down it
// asks its own again. Two things make that true, and both are undone here
// in the opposite order: the adapter's own resolvers
// (SetInterfaceDnsSettings, through winipcfg) and the policy rule for "."
// that keeps Windows from asking anyone else (windows_dns.go).
func (c *winCfg) SetLinkDNS(_ context.Context, ifname string, servers []netip.Addr) error {
	rule, err := winNRPTRule(ifname)
	if err != nil {
		return err
	}
	luid, err := c.adapter(ifname)
	if err != nil {
		return err
	}
	if len(servers) == 0 {
		// the rule goes first: while it is there every name is sent to the
		// tunnel, so it must not outlive the adapter's resolvers
		errs := []error{winDelNRPT(rule)}
		errs = append(errs, luid.SetDNS(windows.AF_INET, nil, nil))
		errs = append(errs, luid.SetDNS(windows.AF_INET6, nil, nil))
		winDNSChanged()
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("%w: %w", ErrNoResolver, err)
		}
		return nil
	}
	var v6 bool
	for _, s := range servers {
		if s.Unmap().Is6() {
			v6 = true
		}
	}
	// SetDNS filters by family itself; v6 only when there is such a server,
	// so a v4-only hub does not clear what the machine has for v6
	if err := luid.SetDNS(windows.AF_INET, servers, nil); err != nil {
		return fmt.Errorf("%w: resolvers on %s: %w", ErrNoResolver, ifname, err)
	}
	if v6 {
		if err := luid.SetDNS(windows.AF_INET6, servers, nil); err != nil {
			return fmt.Errorf("%w: IPv6 resolvers on %s: %w", ErrNoResolver, ifname, err)
		}
	}
	if err := winSetNRPT(rule, servers); err != nil {
		// without the rule Windows would ask the other adapters' resolvers
		// in parallel, so this is not a half success: take the resolvers
		// off again and report
		_ = luid.SetDNS(windows.AF_INET, nil, nil)
		_ = luid.SetDNS(windows.AF_INET6, nil, nil)
		winDNSChanged()
		return fmt.Errorf("%w: %w", ErrNoResolver, err)
	}
	winDNSChanged()
	return nil
}

// winSetNRPT writes the rule that sends every name to these resolvers.
func winSetNRPT(rule string, servers []netip.Addr) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, winNRPTPath+`\`+rule, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("netcfg: name resolution policy %s (needs administrator rights): %w", rule, err)
	}
	defer key.Close()
	// "." is every name; ConfigOptions 8 says the rule names DNS servers,
	// and version 2 is what Windows 8 and later read
	if err := key.SetStringsValue("Name", []string{"."}); err != nil {
		return fmt.Errorf("netcfg: name resolution policy %s: %w", rule, err)
	}
	if err := key.SetStringValue("GenericDNSServers", winNRPTServers(servers)); err != nil {
		return fmt.Errorf("netcfg: name resolution policy %s: %w", rule, err)
	}
	if err := key.SetDWordValue("ConfigOptions", 0x8); err != nil {
		return fmt.Errorf("netcfg: name resolution policy %s: %w", rule, err)
	}
	if err := key.SetDWordValue("Version", 2); err != nil {
		return fmt.Errorf("netcfg: name resolution policy %s: %w", rule, err)
	}
	return nil
}

// winDelNRPT removes it again; a rule that is not there is what teardown
// wants to hear.
func winDelNRPT(rule string) error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, winNRPTPath+`\`+rule)
	if err == nil || errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("netcfg: removing name resolution policy %s: %w", rule, err)
}

// winDNSChanged tells the resolver cache to read its policy again, the way
// winipcfg does after changing an adapter's resolvers.
func winDNSChanged() {
	scm, err := mgr.Connect()
	if err != nil {
		return
	}
	defer scm.Disconnect()
	s := mgr.Service{Name: "dnscache"}
	s.Handle, err = windows.OpenService(scm.Handle, windows.StringToUTF16Ptr(s.Name), windows.SERVICE_PAUSE_CONTINUE)
	if err != nil {
		return
	}
	defer s.Close()
	_, _ = s.Control(svc.ParamChange)
}

// SweepDNS implements DNSSweeper: it removes the policy rules of tunnel
// devices that are gone. These rules are in the registry, so they outlive
// the process and a reboot -- without this, a Windows machine whose daemon
// was killed at the wrong moment would send every name into a tunnel that no
// longer exists, with nothing to tell anyone why (R144).
func (c *winCfg) SweepDNS(_ context.Context) ([]string, error) {
	rules, err := winNRPTRules()
	if err != nil {
		return nil, err
	}
	var gone []string
	for _, r := range rules {
		if ifname := winNRPTIface(r); ifname != "" && !winIfaceExists(ifname) {
			if err := winDelNRPT(r); err != nil {
				return gone, err
			}
			gone = append(gone, winNRPTPath+`\`+r)
		}
	}
	if len(gone) > 0 {
		winDNSChanged()
	}
	return gone, nil
}

// LiveDNSKeys are the rules whose device is still there: a node still owns
// them, and a repair must not take its resolver away.
func (c *winCfg) LiveDNSKeys(_ context.Context) []string {
	rules, _ := winNRPTRules()
	var live []string
	for _, r := range rules {
		if ifname := winNRPTIface(r); ifname != "" && winIfaceExists(ifname) {
			live = append(live, winNRPTPath+`\`+r)
		}
	}
	return live
}

func winNRPTRules() ([]string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, winNRPTPath, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil // no policy table at all: nothing of ours can be in it
	}
	if err != nil {
		return nil, fmt.Errorf("netcfg: reading the name resolution policy table: %w", err)
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("netcfg: reading the name resolution policy table: %w", err)
	}
	return names, nil
}

func winIfaceExists(ifname string) bool {
	_, err := net.InterfaceByName(ifname)
	return err == nil
}
