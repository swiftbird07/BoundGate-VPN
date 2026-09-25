package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
)

// admin sign: the second approval factor. Runs on the admin's machine with
// the security key, talks to the control plane's admin name over HTTPS with
// a one-time token (from the confirm step), and never touches the node
// daemon.
//
//	boundgatectl admin sign --control https://control.example --node ID --fingerprint FP --token T
//	    [--cacert FILE] [--key PRIVATE_KEY_FILE | --agent-key SUBSTRING | --signature FILE | --out FILE]
func runAdmin(args []string, asJSON bool) error {
	if len(args) > 0 && args[0] == "sign-signers" {
		return runAdminSignSigners(args[1:], asJSON)
	}
	if len(args) == 0 || args[0] != "sign" {
		return errors.New("usage: boundgatectl admin sign-signers --control URL --token T [--cacert F] [--key F | --agent-key S | --signature F | --out F] [--yes]\n       boundgatectl admin sign --control URL --node ID --fingerprint FP --token T [--cacert F] [--key F | --agent-key S | --signature F | --out F]")
	}
	fs := flag.NewFlagSet("admin sign", flag.ContinueOnError)
	control := fs.String("control", "", "control plane URL (https://host[:port])")
	cacert := fs.String("cacert", "", "PEM file to trust instead of the system roots (dev, self-signed)")
	nodeID := fs.String("node", "", "node id from the confirm step")
	fp := fs.String("fingerprint", "", "the node's key fingerprint you compared (64 hex digits, spaces allowed)")
	token := fs.String("token", "", "one-time sign token from the confirm step")
	keyFile := fs.String("key", "", "sign with this OpenSSH private key file, without ssh-agent; a passphrase protected file or a security key (YubiKey) is signed by ssh-keygen, which asks for passphrase, PIN and touch")
	agentKey := fs.String("agent-key", "", "pick the ssh-agent key whose comment or fingerprint contains this")
	sigFile := fs.String("signature", "", "post this SSHSIG file made with `ssh-keygen -Y sign -n boundgate-binding` (a revocation: -n boundgate-revocation) instead of signing")
	outFile := fs.String("out", "", "write the binding (or revocation) to this file for `ssh-keygen -Y sign` and exit")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *control == "" || *nodeID == "" || *fp == "" || *token == "" {
		return errors.New("admin sign: --control, --node, --fingerprint and --token are required")
	}
	c, err := newAdminHTTP(*control, *cacert)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var sb api.SignBinding
	if err := c.call(ctx, *token, "GET", "/api/v1/sign/binding", nil, &sb); err != nil {
		return err
	}
	// Two independent checks: the token is bound to the node and its key on
	// the server, and the admin's own copy of the fingerprint must match.
	wantFP := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(*fp), " ", ""))
	gotFP := strings.ReplaceAll(sb.Fingerprint, " ", "")
	if sb.NodeID != *nodeID {
		return fmt.Errorf("admin sign: token belongs to node %s, not %s", sb.NodeID, *nodeID)
	}
	if wantFP != gotFP {
		return fmt.Errorf("admin sign: fingerprint mismatch: you gave %s, the control plane has %s. Do not sign", wantFP, gotFP)
	}
	// What gets signed is the statement, so that is what is checked and
	// shown: the fields next to it are the control plane's description of
	// it. The namespace is this tool's, never the control plane's word: a
	// signature in another namespace could be taken for something else.
	var (
		msg       []byte
		namespace string
		issued    int64
	)
	if sb.Revocation != "" {
		rv, err := binding.ParseRevocation([]byte(sb.Revocation))
		if err != nil {
			return fmt.Errorf("admin sign: the control plane sent a revocation that does not parse: %w. Do not sign", err)
		}
		if rv.NodeID != *nodeID {
			return fmt.Errorf("admin sign: the revocation is for node %s, not %s. Do not sign", rv.NodeID, *nodeID)
		}
		if got := strings.ReplaceAll(rv.SPKI.Fingerprint(), " ", ""); got != wantFP {
			return fmt.Errorf("admin sign: the revocation names the key %s, you gave %s. Do not sign", got, wantFP)
		}
		msg, namespace, issued = []byte(sb.Revocation), binding.RevocationNamespace, rv.Issued
		if !asJSON {
			fmt.Printf("REVOKE node:  %s (%s)\nfingerprint:  %s\nnetwork:      %s\nrevocation:   %s\n\nEvery node will refuse this node's bindings issued before now, for good.\n",
				sb.Name, rv.NodeID, rv.SPKI.Fingerprint(), orUnknown(rv.Deployment), sb.Revocation)
		}
	} else {
		bd, err := binding.Parse([]byte(sb.Binding))
		if err != nil {
			return fmt.Errorf("admin sign: the control plane sent a binding that does not parse: %w. Do not sign", err)
		}
		if bd.NodeID != *nodeID {
			return fmt.Errorf("admin sign: the binding is for node %s, not %s. Do not sign", bd.NodeID, *nodeID)
		}
		if got := strings.ReplaceAll(bd.SPKI.Fingerprint(), " ", ""); got != wantFP {
			return fmt.Errorf("admin sign: the binding names the key %s, you gave %s. Do not sign", got, wantFP)
		}
		msg, namespace, issued = []byte(sb.Binding), binding.Namespace, bd.Issued
		if !asJSON {
			fmt.Printf("node:         %s (%s)\nfingerprint:  %s\nkey:          %s (hardware-bound: %v)\nkind:         %s\nroles:        %v\n",
				sb.Name, bd.NodeID, bd.SPKI.Fingerprint(), sb.KeyKind, bd.HardwareBound, bd.Kind, bd.Roles)
			if len(bd.Tags) > 0 {
				fmt.Printf("tags:         %s\n", strings.Join(bd.Tags, ", "))
			}
			for _, p := range bd.Prefixes {
				fmt.Printf("announces:    %s (%s)\n", p.Prefix, p.Mode)
			}
			fmt.Printf("overlay ip:   %s\nnetwork:      %s\n", bd.OverlayIP, orUnknown(bd.Deployment))
			if sb.PublicAddr != "" {
				fmt.Printf("public addr:  %s (not signed)\n", sb.PublicAddr)
			}
			fmt.Printf("binding:      %s\n", sb.Binding)
		}
	}
	// A statement dated far from now is refused: dated in the future it
	// would outrank every later binding of the node (nodes keep the newest),
	// and nothing an admin signs today should say otherwise.
	if issued != 0 {
		if d := time.Since(time.Unix(issued, 0)); d > 24*time.Hour || d < -24*time.Hour {
			return fmt.Errorf("admin sign: the statement is dated %s, more than a day from this machine's clock. Do not sign", time.Unix(issued, 0).UTC().Format(time.RFC3339))
		}
	}
	if *outFile != "" {
		if err := os.WriteFile(*outFile, msg, 0o600); err != nil {
			return err
		}
		fmt.Printf("\nstatement written to %s. Sign it with:\n  ssh-keygen -Y sign -n %s -f <key> %s\nthen run this command again with --signature %s.sig\n", *outFile, namespace, *outFile, *outFile)
		return nil
	}

	var sig string
	switch {
	case *sigFile != "":
		b, err := os.ReadFile(*sigFile)
		if err != nil {
			return err
		}
		sig = string(b)
	default:
		var err error
		if sig, err = signMessage(*keyFile, *agentKey, sb.Signers, namespace, msg, asJSON); err != nil {
			return err
		}
	}
	// verify locally before sending so a wrong key fails here, not there
	signers, err := binding.ParseSigners([]byte(strings.Join(sb.Signers, "\n")))
	if err != nil {
		return err
	}
	if sb.Revocation != "" {
		_, err = binding.VerifyRevocation(registry.SignedRevocation{Revocation: sb.Revocation, Signature: sig}, signers, nil)
	} else {
		_, err = binding.Verify(msg, sig, signers)
	}
	if err != nil {
		return fmt.Errorf("admin sign: the signature does not verify against the registered admin keys: %w", err)
	}
	var nv api.NodeView
	if err := c.call(ctx, *token, "POST", "/api/v1/sign/signature", api.SignatureBody{Signature: sig}, &nv); err != nil {
		return err
	}
	if asJSON {
		return dump(nv)
	}
	if sb.Revocation != "" {
		fmt.Printf("\nrevocation signed: %s stays revoked on every node, whatever the control plane says later\n", nv.Name)
		return nil
	}
	fmt.Printf("\napproved: %s is now %s (overlay ip %s, signed by %s)\n", nv.Name, nv.Status, nv.OverlayIP, nv.SignedBy)
	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "(not named: signed before networks were named)"
	}
	return s
}

// pickSigner returns the ssh-agent key that is one of the registered admin
// keys (narrowed by --agent-key). Key files: signMessage.
func pickSigner(agentKey string, registered []string) (ssh.Signer, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errors.New("admin sign: no --key and SSH_AUTH_SOCK is not set; pass --key <private key file>, or start ssh-agent and add the admin key")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("admin sign: ssh-agent: %w", err)
	}
	ag := agent.NewClient(conn)
	signers, err := ag.Signers()
	if err != nil {
		return nil, fmt.Errorf("admin sign: ssh-agent: %w", err)
	}
	allowed, err := binding.ParseSigners([]byte(strings.Join(registered, "\n")))
	if err != nil {
		return nil, err
	}
	var candidates []ssh.Signer
	for _, s := range signers {
		if !allowed.Contains(s.PublicKey()) {
			continue
		}
		if agentKey != "" {
			fp := ssh.FingerprintSHA256(s.PublicKey())
			comment := ""
			if k, ok := s.PublicKey().(*agent.Key); ok {
				comment = k.Comment
			}
			if !strings.Contains(fp, agentKey) && !strings.Contains(comment, agentKey) {
				continue
			}
		}
		candidates = append(candidates, s)
	}
	switch len(candidates) {
	case 0:
		return nil, errors.New("admin sign: no key in ssh-agent matches a registered admin key. A security key (YubiKey) is usually not in the agent: name its key file, --key ~/.ssh/<your admin key>, and ssh-keygen asks for PIN and touch")
	case 1:
		return candidates[0], nil
	default:
		var fps []string
		for _, s := range candidates {
			fps = append(fps, ssh.FingerprintSHA256(s.PublicKey()))
		}
		return nil, fmt.Errorf("admin sign: several registered keys in ssh-agent (%s); choose one with --agent-key", strings.Join(fps, ", "))
	}
}

type adminHTTP struct {
	base string
	c    *http.Client
}

func newAdminHTTP(base, cacert string) (*adminHTTP, error) {
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(base, "https://") {
		return nil, errors.New("admin sign: --control must be an https:// URL")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if cacert != "" {
		pem, err := os.ReadFile(cacert)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("admin sign: %s: no certificate found", cacert)
		}
		tlsCfg.RootCAs = pool
	}
	return &adminHTTP{base: base, c: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}}, nil
}

func (a *adminHTTP) call(ctx context.Context, token, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rsp, err := a.c.Do(req)
	if err != nil {
		return fmt.Errorf("admin sign: %w", err)
	}
	defer rsp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(rsp.Body, 1<<20))
	if rsp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(b))
		}
		return fmt.Errorf("admin sign: control plane: HTTP %d: %s", rsp.StatusCode, e.Error)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}
