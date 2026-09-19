package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
)

// signMessage returns the armored SSHSIG over message. With --key it signs
// then and there and keeps nothing loaded afterwards: a plain key file is
// used directly, anything this program cannot use itself (a passphrase
// protected file, a security key's handle) goes to ssh-keygen, which asks for
// passphrase, PIN and touch on the terminal. Without --key it asks ssh-agent.
// The caller verifies the result, so a wrong key fails before anything is sent.
func signMessage(keyFile, agentKey string, registered []string, namespace string, message []byte, quiet bool) (string, error) {
	if keyFile == "" {
		signer, err := pickSigner(agentKey, registered)
		if err != nil {
			return "", err
		}
		if !quiet {
			fmt.Printf("signing with: %s %s (ssh-agent)\n", signer.PublicKey().Type(), ssh.FingerprintSHA256(signer.PublicKey()))
			if binding.IsHardwareKey(signer.PublicKey()) {
				fmt.Println("touch your security key now")
			}
		}
		sig, err := binding.Sign(signer, namespace, message)
		if err != nil {
			return "", fmt.Errorf("%w\nthe agent holds the key but could not sign with it (the ssh-agent of macOS cannot use security keys, and an agent without an askpass program cannot ask for the PIN). Sign without an agent instead: --key <private key file>", err)
		}
		return sig, nil
	}
	b, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	if signer, err := ssh.ParsePrivateKey(b); err == nil {
		if !quiet {
			fmt.Printf("signing with: %s %s\n", signer.PublicKey().Type(), ssh.FingerprintSHA256(signer.PublicKey()))
		}
		return binding.Sign(signer, namespace, message)
	}
	return signWithSSHKeygen(keyFile, namespace, message, quiet)
}

func signWithSSHKeygen(keyFile, namespace string, message []byte, quiet bool) (string, error) {
	bin, err := findSSHKeygen()
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "boundgate-sign-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	msg := filepath.Join(dir, "message")
	if err := os.WriteFile(msg, message, 0o600); err != nil {
		return "", err
	}
	if !quiet {
		fmt.Printf("signing with: %s via %s\nit asks for the passphrase of the file and, for a security key, for PIN and touch\n", keyFile, bin)
	}
	cmd := exec.Command(bin, "-Y", "sign", "-n", namespace, "-f", keyFile, msg)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		hint := ""
		if runtime.GOOS == "darwin" && bin == "/usr/bin/ssh-keygen" {
			hint = " (the ssh-keygen of macOS cannot use security keys: brew install openssh, or set BOUNDGATE_SSH_KEYGEN)"
		}
		return "", fmt.Errorf("admin sign: %s: %w%s", bin, err, hint)
	}
	sig, err := os.ReadFile(msg + ".sig")
	if err != nil {
		return "", err
	}
	return string(sig), nil
}

// findSSHKeygen prefers an OpenSSH that can talk to security keys: the one
// macOS ships is built without that, Homebrew's is not.
func findSSHKeygen() (string, error) {
	if p := os.Getenv("BOUNDGATE_SSH_KEYGEN"); p != "" {
		return p, nil
	}
	if runtime.GOOS == "darwin" {
		for _, p := range []string{"/opt/homebrew/bin/ssh-keygen", "/usr/local/bin/ssh-keygen"} {
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return "", errors.New("admin sign: this key file needs ssh-keygen (OpenSSH), which was not found")
	}
	return p, nil
}
