package devicekey_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey/softkey"
)

func TestSoftkeyCreateLoadAndSign(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "device.key")
	k1, err := softkey.New(path).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if k1.HardwareBound() || k1.Kind() != "softkey" {
		t.Fatal("softkey must report not hardware-bound")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, want 0600", st.Mode().Perm())
	}
	k2, err := softkey.New(path).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h1, _ := devicekey.HashPublicKey(k1.Public())
	h2, _ := devicekey.HashPublicKey(k2.Public())
	if h1 != h2 {
		t.Fatal("reloading the key store changed the public key")
	}

	digest := sha256.Sum256([]byte("challenge"))
	sig, err := k2.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(k1.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("signature does not verify")
	}
}

func TestSPKIHashRoundTrip(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h, err := devicekey.HashPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if h.IsZero() {
		t.Fatal("zero hash")
	}
	if len(h.String()) != 64 {
		t.Fatalf("hex length %d", len(h.String()))
	}
	fp := h.Fingerprint()
	if len(fp) != 64+15 {
		t.Fatalf("fingerprint %q", fp)
	}
	for _, s := range []string{h.String(), fp, " " + fp + "\n"} {
		p, err := devicekey.ParseSPKIHash(s)
		if err != nil || p != h {
			t.Fatalf("parse %q: %v", s, err)
		}
	}
	if _, err := devicekey.ParseSPKIHash("abc"); err == nil {
		t.Fatal("short hash accepted")
	}
	txt, _ := h.MarshalText()
	var back devicekey.SPKIHash
	if err := back.UnmarshalText(txt); err != nil || back != h {
		t.Fatal("text round trip failed")
	}
}

func TestCheckPublicKey(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := devicekey.CheckPublicKey(&p256.PublicKey); err != nil {
		t.Fatal(err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err := devicekey.CheckPublicKey(&p384.PublicKey); err == nil {
		t.Fatal("P-384 accepted")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := devicekey.CheckPublicKey(&rsaKey.PublicKey); err == nil {
		t.Fatal("RSA accepted")
	}
}
