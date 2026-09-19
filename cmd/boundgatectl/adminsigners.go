package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
)

// runAdminSignSigners signs the next version of the admin key list.
//
// The administrator's signature is what makes a list valid on every node,
// so this command trusts the control plane with nothing: it verifies the
// current chain itself, checks that the proposal continues exactly that
// chain, and prints the resulting list from the very bytes it is about to
// sign. It also keeps its own pin of the list per control plane (like a
// node does), so a control plane that presents another history to get a
// signature on a forked chain is caught here.
func runAdminSignSigners(args []string, asJSON bool) error {
	fs := flag.NewFlagSet("admin sign-signers", flag.ContinueOnError)
	control := fs.String("control", "", "control plane URL (https://host[:port])")
	cacert := fs.String("cacert", "", "PEM file to trust instead of the system roots (dev, self-signed)")
	token := fs.String("token", "", "one-time token from the admin UI")
	keyFile := fs.String("key", "", "sign with this OpenSSH private key file, without ssh-agent; a passphrase protected file or a security key (YubiKey) is signed by ssh-keygen, which asks for passphrase, PIN and touch")
	agentKey := fs.String("agent-key", "", "pick the ssh-agent key whose comment or fingerprint contains this")
	sigFile := fs.String("signature", "", "post this SSHSIG file made with `ssh-keygen -Y sign -n boundgate-signers` instead of signing")
	outFile := fs.String("out", "", "write the list to this file for `ssh-keygen -Y sign` and exit")
	yes := fs.Bool("yes", false, "do not ask for confirmation (scripts)")
	pinDir := fs.String("pin-dir", "", "where this machine remembers the admin key list per control plane (default: your config directory)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *control == "" || *token == "" {
		return errors.New("admin sign-signers: --control and --token are required")
	}
	c, err := newAdminHTTP(*control, *cacert)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var p api.SignSigners
	if err := c.call(ctx, *token, "GET", "/api/v1/sign/signers", nil, &p); err != nil {
		return err
	}
	if p.Namespace != binding.SignersNamespace {
		return fmt.Errorf("admin sign-signers: the control plane asks for namespace %q; refusing", p.Namespace)
	}

	// 1. what this machine knows, 2. the chain as the control plane has it
	pinPath, pinned, err := loadSignerPin(*pinDir, *control)
	if err != nil {
		return err
	}
	head, err := binding.VerifyChain(pinned, p.Chain, "")
	if err != nil {
		return fmt.Errorf("admin sign-signers: the control plane's admin key chain does not continue what this machine knows (%s): %w. Do not sign", pinPath, err)
	}
	// 3. the proposal must be exactly the next link
	set, err := binding.ParseSignerSet([]byte(p.Set))
	if err != nil {
		return fmt.Errorf("admin sign-signers: proposal: %w", err)
	}
	if set.Version != head.Version+1 || set.Prev != head.Hash {
		return fmt.Errorf("admin sign-signers: the proposal (version %d) does not continue the current list (version %d). Do not sign", set.Version, head.Version)
	}
	allowed := head.Keys
	if head.Version == 0 {
		allowed = set.Keys // the first list is signed by one of its own keys
	}

	if !asJSON {
		if head.Version == 0 {
			fmt.Printf("first admin key list (version 1) for %s\n", *control)
		} else {
			fmt.Printf("admin key list for %s: version %d -> %d\n", *control, head.Version, set.Version)
		}
		for _, k := range set.Keys {
			mark := "  keep"
			if !slices.Contains(head.Keys, k) {
				mark = "+ ADD "
			}
			fmt.Printf("  %s  %s  %s\n", mark, keyFP(k), p.Names[k])
		}
		for _, k := range head.Keys {
			if !slices.Contains(set.Keys, k) {
				fmt.Printf("  - DROP  %s  %s\n", keyFP(k), p.Names[k])
			}
		}
		fmt.Println("Every key in this list can approve nodes and change this list. Compare the fingerprints with the keys' owners.")
	}
	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(p.Set), 0o600); err != nil {
			return err
		}
		fmt.Printf("\nlist written to %s. Sign it with:\n  ssh-keygen -Y sign -n %s -f <key> %s\nthen run this command again with --signature %s.sig\n", *outFile, p.Namespace, *outFile, *outFile)
		return nil
	}
	if !*yes {
		fmt.Print("Sign this list? Type yes: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			return errors.New("admin sign-signers: not signed")
		}
	}

	var sig string
	if *sigFile != "" {
		b, err := os.ReadFile(*sigFile)
		if err != nil {
			return err
		}
		sig = string(b)
	} else {
		if sig, err = signMessage(*keyFile, *agentKey, allowed, binding.SignersNamespace, []byte(p.Set), asJSON); err != nil {
			return err
		}
	}
	// 4. verify our own signature the way a node will, before posting it
	next, err := binding.VerifyChain(head, append(slices.Clone(p.Chain), binding.SignedSet{Set: p.Set, Signature: sig}), "")
	if err != nil || next.Version != set.Version {
		return fmt.Errorf("admin sign-signers: the signature would not be accepted by nodes: %v", err)
	}
	var out map[string]any
	if err := c.call(ctx, *token, "POST", "/api/v1/sign/signers", api.SignatureBody{Signature: sig}, &out); err != nil {
		return err
	}
	if err := saveSignerPin(pinPath, next); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not remember the new list in %s: %v\n", pinPath, err)
	}
	if asJSON {
		return dump(out)
	}
	fmt.Printf("\nadmin key list is now version %d (%d keys). Nodes follow with their next snapshot.\n", next.Version, len(next.Keys))
	if d, ok := out["demoted_nodes"].([]any); ok && len(d) > 0 {
		fmt.Printf("%d node(s) were signed by a removed key and need a new signature: %v\n", len(d), d)
	}
	return nil
}

func keyFP(k string) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
	if err != nil {
		return k
	}
	return pub.Type() + " " + ssh.FingerprintSHA256(pub)
}

// The pin of this machine: the list it last saw (and helped to sign), per
// control plane host.
func loadSignerPin(dir, control string) (string, binding.Trust, error) {
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return "", binding.Trust{}, err
		}
		dir = filepath.Join(base, "boundgate", "signers")
	}
	u, err := url.Parse(control)
	if err != nil || u.Host == "" {
		return "", binding.Trust{}, errors.New("admin sign-signers: --control is not a URL")
	}
	path := filepath.Join(dir, strings.NewReplacer(":", "_", "/", "_").Replace(u.Host)+".json")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return path, binding.Trust{}, nil
	}
	if err != nil {
		return path, binding.Trust{}, err
	}
	var t binding.Trust
	if err := json.Unmarshal(raw, &t); err != nil || !t.Pinned() {
		return path, binding.Trust{}, fmt.Errorf("admin sign-signers: %s is damaged; check it (or remove it to trust the control plane's chain once)", path)
	}
	return path, t, nil
}

func saveSignerPin(path string, t binding.Trust) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
