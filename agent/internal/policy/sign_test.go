package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "policy.key")
	pubPath := filepath.Join(dir, "policy.pub")
	bundlePath := filepath.Join(dir, "policy.yaml")

	if _, err := Keygen(keyPath, pubPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, []byte(validBundle), 0o600); err != nil {
		t.Fatal(err)
	}
	priv, err := LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignFile(bundlePath, priv); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(bundlePath, pub); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "policy.key")
	pubPath := filepath.Join(dir, "policy.pub")
	bundlePath := filepath.Join(dir, "policy.yaml")

	if _, err := Keygen(keyPath, pubPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, []byte(validBundle), 0o600); err != nil {
		t.Fatal(err)
	}
	priv, _ := LoadPrivateKey(keyPath)
	pub, _ := LoadPublicKey(pubPath)
	if err := SignFile(bundlePath, priv); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, []byte(validBundle+"\n# tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(bundlePath, pub); err == nil {
		t.Fatal("expected verify failure")
	}
}

func TestKeygenPermissions(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "policy.key")
	pubPath := filepath.Join(dir, "policy.pub")
	if _, err := Keygen(keyPath, pubPath); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key perm=%o want 0600", st.Mode().Perm())
	}
}
