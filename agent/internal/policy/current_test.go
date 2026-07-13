package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCurrentHappyPath(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "policy.key")
	pubPath := filepath.Join(dir, "policy.pub")
	bundlePath := filepath.Join(dir, "policy.yaml")
	storePath := filepath.Join(dir, "store")

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
	if err := SignFile(bundlePath, priv); err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	loader := &Loader{Store: store, PubKey: pub}
	if _, err := loader.Load(FileSource{BundlePath: bundlePath}); err != nil {
		t.Fatal(err)
	}

	cp, meta, err := LoadCurrent(store, pub)
	if err != nil {
		t.Fatal(err)
	}
	if cp == nil || meta.Version != 1 {
		t.Fatalf("bad load: cp=%v meta=%+v", cp, meta)
	}
	if len(cp.Live) != 1 || len(cp.Shadow) != 1 {
		t.Fatalf("live=%d shadow=%d", len(cp.Live), len(cp.Shadow))
	}
}

func TestLoadCurrentNoVersion(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "policy.pub")
	keyPath := filepath.Join(dir, "policy.key")
	if _, err := Keygen(keyPath, pubPath); err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = LoadCurrent(store, pub)
	if err == nil || err.Error() != "no current policy version" {
		t.Fatalf("expected no current error, got %v", err)
	}
}

func TestLoadCurrentRejectsTamperedBundle(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "policy.key")
	pubPath := filepath.Join(dir, "policy.pub")
	bundlePath := filepath.Join(dir, "policy.yaml")
	storePath := filepath.Join(dir, "store")

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
	if err := SignFile(bundlePath, priv); err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	loader := &Loader{Store: store, PubKey: pub}
	if _, err := loader.Load(FileSource{BundlePath: bundlePath}); err != nil {
		t.Fatal(err)
	}

	verDir := filepath.Join(storePath, versionsDir, "1", "bundle.yaml")
	data, err := os.ReadFile(verDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(verDir, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err = LoadCurrent(store, pub)
	if err == nil {
		t.Fatal("expected verify failure")
	}
}
