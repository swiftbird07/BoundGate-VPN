// boundgatectl controls the local boundgate-node daemon.
//
//	boundgatectl status
//	boundgatectl identity
//	boundgatectl configure -control HOST[:PORT]   a node without a configured control plane (setup mode)
//	boundgatectl reset                     forget the control plane (keeps the device key)
//	boundgatectl enroll [-name NAME]
//	boundgatectl profiles
//	boundgatectl up [-profile NAME]
//	boundgatectl down
//	boundgatectl login [-timeout 10m]      prints the login URL, waits for the browser login
//	boundgatectl logout
//	boundgatectl flows                     tracked flows with their ACL decision
//	boundgatectl admin sign --control URL --node ID --fingerprint FP --token T   (admin side, see adminsign.go)
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/ipc"
)

func main() {
	defSocket := "/run/boundgate/node.sock"
	if runtime.GOOS == "darwin" {
		defSocket = "/var/run/boundgate/node.sock"
	}
	if v := os.Getenv("BOUNDGATE_SOCKET"); v != "" {
		defSocket = v
	}
	socket := flag.String("socket", defSocket, "node daemon socket (or $BOUNDGATE_SOCKET)")
	asJSON := flag.Bool("json", false, "print raw JSON")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: boundgatectl [-socket PATH] [-json] status|identity|configure -control HOST|reset|enroll [-name NAME]|profiles|up [-profile NAME]|down|login [-timeout D]|logout|flows\n"+
			"       boundgatectl [-json] admin sign --control URL --node ID --fingerprint FP --token T [--cacert F] [--key F|--agent-key S|--signature F|--out F]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if flag.Arg(0) == "admin" {
		if err := runAdmin(flag.Args()[1:], *asJSON); err != nil {
			fmt.Fprintln(os.Stderr, "boundgatectl:", err)
			os.Exit(1)
		}
		return
	}
	c := ipc.NewClient(*socket)
	if err := run(c, flag.Args(), *asJSON); err != nil {
		fmt.Fprintln(os.Stderr, "boundgatectl:", err)
		os.Exit(1)
	}
}

func run(c *ipc.Client, args []string, asJSON bool) error {
	switch args[0] {
	case "status":
		s, err := c.Status()
		if err != nil {
			return err
		}
		return printStatus(s, asJSON)
	case "identity":
		s, err := c.Status()
		if err != nil {
			return err
		}
		if asJSON {
			return dump(map[string]any{"node_name": s.NodeName, "node_id": s.NodeID, "spki": s.SPKI, "fingerprint": s.Fingerprint, "key_kind": s.KeyKind, "hardware_bound": s.HardwareBound,
				"enrollment": s.Enrollment, "control": s.Control, "control_pin": s.ControlPin, "admin_keys": s.AdminKeys, "binding": s.Binding})
		}
		fmt.Printf("node:         %s\nkey:          %s (hardware-bound: %v)\nspki:         %s\nfingerprint:  %s\nenrollment:   %s\n", s.NodeName, s.KeyKind, s.HardwareBound, s.SPKI, s.Fingerprint, s.Enrollment)
		fmt.Printf("control:      %s\ncontrol pin:  %s\n", s.Control, orNone(s.ControlPin))
		if len(s.AdminKeys) == 0 {
			fmt.Println("admin keys:   none pinned yet (pinned at enrollment)")
		}
		for i, k := range s.AdminKeys {
			label := "admin keys:  "
			if i > 0 {
				label = "             "
			}
			fmt.Printf("%s %s\n", label, k)
		}
		if s.Binding != "" {
			fmt.Printf("binding:      %s\n", s.Binding)
		}
		return nil
	case "enroll":
		fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
		name := fs.String("name", "", "node name shown to the admin (default: configured name)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		st, err := c.Enroll(*name)
		if err != nil {
			return err
		}
		if asJSON {
			return dump(st)
		}
		fmt.Printf("status:       %s\nnode id:      %s\nname:         %s\nfingerprint:  %s\n", st.Status, st.NodeID, st.Name, st.Fingerprint)
		switch st.Status {
		case "pending":
			fmt.Println("\nWaiting for approval. Give the fingerprint above to your administrator;")
			fmt.Println("they must compare it with the request before approving.")
		case "approved":
			fmt.Printf("\nThis node is approved (overlay address %s). Use `boundgatectl up`.\n", st.OverlayIP)
		case "revoked":
			fmt.Println("\nThis node key was revoked. Delete the node state to create a new key and enroll again.")
		}
		return nil
	case "configure":
		fs := flag.NewFlagSet("configure", flag.ContinueOnError)
		control := fs.String("control", "", "control plane address, host[:port] (required)")
		serverName := fs.String("server-name", "", "TLS name of its node channel (default: nodes.<host>)")
		name := fs.String("name", "", "name of this node (default: host name)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := c.Configure(ipc.Settings{ControlAddr: *control, ControlServerName: *serverName, Name: *name}); err != nil {
			return err
		}
		fmt.Println("configured. Next: `boundgatectl enroll`, and compare the control pin it shows with your administrator's.")
		return nil
	case "reset":
		if err := c.Reset(); err != nil {
			return err
		}
		fmt.Println("the node forgot its control plane (the device key is kept). Next: `boundgatectl configure -control HOST`.")
		return nil
	case "profiles":
		names, err := c.Profiles()
		if err != nil {
			return err
		}
		if asJSON {
			return dump(names)
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	case "up":
		fs := flag.NewFlagSet("up", flag.ContinueOnError)
		prof := fs.String("profile", "", "routing profile (default: the daemon's configured profile, else everything advertised)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		s, err := c.Up(*prof)
		if err != nil {
			return err
		}
		return printStatus(s, asJSON)
	case "down":
		s, err := c.Down()
		if err != nil {
			return err
		}
		return printStatus(s, asJSON)
	case "login":
		fs := flag.NewFlagSet("login", flag.ContinueOnError)
		timeout := fs.Duration("timeout", 10*time.Minute, "how long to wait for the browser login")
		noWait := fs.Bool("no-wait", false, "print the URL and return; poll with `boundgatectl status`")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		st, err := c.Login()
		if err != nil {
			return err
		}
		if asJSON && *noWait {
			return dump(st)
		}
		if !asJSON {
			fmt.Printf("Open this URL in your browser and log in:\n\n  %s\n\n", st.URL)
		}
		if *noWait {
			return nil
		}
		deadline := time.Now().Add(*timeout)
		for time.Now().Before(deadline) {
			res, err := c.LoginWait(st.FlowID, 25*time.Second)
			if err != nil {
				return err
			}
			switch res.Status {
			case "done":
				if asJSON {
					return dump(res)
				}
				u := res.Session
				who := u.Username
				if who == "" {
					who = u.Subject
				}
				fmt.Printf("logged in as %s (%s) groups %v until %s\n", who, u.Email, u.Groups, u.ExpiresAt.Local().Format("2006-01-02 15:04"))
				return nil
			case "failed":
				return fmt.Errorf("login failed: %s", res.Error)
			}
		}
		return errors.New("login timed out; run `boundgatectl login` again")
	case "logout":
		s, err := c.Logout()
		if err != nil {
			return err
		}
		return printStatus(s, asJSON)
	case "flows":
		fl, err := c.Flows()
		if err != nil {
			return err
		}
		if asJSON {
			return dump(fl)
		}
		if len(fl) == 0 {
			fmt.Println("no tracked flows")
			return nil
		}
		fmt.Printf("%-8s %-6s %-22s %-22s %-5s %-8s %-16s %-14s %10s %10s  %s\n", "FLOW", "PROTO", "SOURCE", "DESTINATION", "DEC", "FROM", "USER", "NAME", "IN", "OUT", "POLICIES")
		for _, f := range fl {
			name := f.SNI
			if name == "" {
				name = f.DNSName
			}
			from := f.PrincipalName
			if f.Local {
				from = "local"
			}
			fmt.Printf("%-8s %-6s %-22s %-22s %-5s %-8.8s %-16.16s %-14.14s %10d %10d  %s\n", f.ID, f.Proto, f.Src, f.Dst, f.Decision, from, f.User, name, f.BytesIn, f.BytesOut, strings.Join(f.Policies, ","))
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printStatus(s node.Status, asJSON bool) error {
	if asJSON {
		return dump(s)
	}
	fmt.Printf("state:        %s\n", s.State)
	if s.State == ipc.StateUnconfigured {
		fmt.Println("no control plane yet: boundgatectl configure -control HOST[:PORT]")
		return nil
	}
	if s.State != node.StateDown {
		fmt.Printf("profile:      %s\noverlay ip:   %s\nroles:        %v\n", s.Profile, s.OverlayIP, s.Roles)
		if len(s.Prefixes) > 0 {
			fmt.Printf("announces:    %s\n", strings.Join(s.Prefixes, ", "))
		}
		for _, h := range s.Hubs {
			mark := " "
			if h.Primary {
				mark = "*"
			}
			line := fmt.Sprintf("hub %s        %s (%s) %s", mark, h.Name, h.Addr, h.State)
			if h.Transport == "tcp" {
				line += " over TCP (UDP blocked?)"
			}
			if h.Error != "" {
				line += ": " + h.Error
			}
			fmt.Println(line)
		}
		if len(s.Routes) > 0 {
			fmt.Printf("routes:       %s\n", strings.Join(s.Routes, ", "))
		}
		if len(s.SkippedRoutes) > 0 {
			fmt.Printf("not routed:   %s\n", strings.Join(s.SkippedRoutes, "; "))
		}
		if s.Tunnels > 0 {
			fmt.Printf("tunnels:      %d\n", s.Tunnels)
		}
		fmt.Printf("flows:        %d tracked, %d denied\n", s.Flows, s.FlowsDenied)
		fmt.Printf("since:        %s\n", s.Since.Format("2006-01-02 15:04:05"))
	}
	if s.LastError != "" {
		fmt.Printf("last error:   %s\n", s.LastError)
	}
	if s.BindingError != "" {
		fmt.Printf("binding:      INVALID: %s\n", s.BindingError)
	}
	if s.ControlError != "" {
		fmt.Printf("control:      ERROR: %s\n", s.ControlError)
	}
	for _, p := range s.IgnoredPeers {
		fmt.Printf("ignored peer: %s\n", p)
	}
	if s.Enrollment == "approved" {
		fmt.Printf("policies:     %d", s.Policies)
		if s.Policies == 0 {
			fmt.Printf(" (nothing is permitted until an admin adds one)")
		}
		fmt.Println()
	}
	for _, p := range s.PolicyErrors {
		fmt.Printf("policy error: %s\n", p)
	}
	if s.LastClose != "" {
		fmt.Printf("last close:   %s\n", s.LastClose)
	}
	if s.User != nil {
		who := s.User.Username
		if who == "" {
			who = s.User.Subject
		}
		fmt.Printf("user:         %s %v until %s\n", who, s.User.Groups, s.User.ExpiresAt.Local().Format("2006-01-02 15:04"))
	} else if s.Kind == "interactive" && s.Enrollment == "approved" {
		fmt.Printf("user:         not logged in (boundgatectl login)\n")
	}
	if s.LoginRequired {
		fmt.Printf("LOGIN REQUIRED: a hub refused this node; run `boundgatectl login`\n")
	}
	fmt.Printf("enrollment:   %s", s.Enrollment)
	if s.EnrollmentError != "" {
		fmt.Printf(" (%s)", s.EnrollmentError)
	} else if s.Enrollment == "unknown" {
		fmt.Printf(" (the control plane does not know this key: never enrolled, or the request was rejected; run `boundgatectl enroll`)")
	}
	fmt.Printf("\nnode:         %s (%s, hardware-bound: %v)\nfingerprint:  %s\nsnapshot:     v%d from %s\n", s.NodeName, s.KeyKind, s.HardwareBound, s.Fingerprint, s.SnapshotVersion, s.Control)
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func dump(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
