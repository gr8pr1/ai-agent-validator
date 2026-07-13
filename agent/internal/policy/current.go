package policy

import (
	"crypto/ed25519"
	"fmt"
)

// LoadCurrent reads the store's current version, verifies the bundle signature,
// and returns a freshly compiled policy. The agent does not trust stored
// compiled.json (decision 9A).
func LoadCurrent(store VersionStore, pub ed25519.PublicKey) (*CompiledPolicy, VersionMeta, error) {
	ver, err := store.Current()
	if err != nil {
		return nil, VersionMeta{}, err
	}
	if ver == 0 {
		return nil, VersionMeta{}, fmt.Errorf("no current policy version")
	}
	stored, err := store.Get(ver)
	if err != nil {
		return nil, VersionMeta{}, err
	}
	if err := Verify(stored.Bundle, stored.Sig, pub); err != nil {
		return nil, VersionMeta{}, fmt.Errorf("verify: %w", err)
	}
	b, err := Parse(stored.Bundle)
	if err != nil {
		return nil, VersionMeta{}, fmt.Errorf("parse: %w", err)
	}
	compiled, err := Compile(b)
	if err != nil {
		return nil, VersionMeta{}, fmt.Errorf("compile: %w", err)
	}
	return compiled, stored.Meta, nil
}
