package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoaderEndToEnd(t *testing.T) {
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
	res, err := loader.Load(FileSource{BundlePath: bundlePath})
	if err != nil {
		t.Fatal(err)
	}
	if res.Compiled == nil || res.Meta.Version != 1 {
		t.Fatalf("bad result: %+v", res)
	}
	cur, _ := store.Current()
	if cur != 1 {
		t.Fatalf("current=%d", cur)
	}
}
