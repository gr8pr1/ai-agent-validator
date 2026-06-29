package policy

import (
	"crypto/ed25519"
	"fmt"
	"os"
)

// Source fetches a signed policy bundle from a pluggable backend.
type Source interface {
	Fetch() (bundle, sig []byte, err error)
}

// FileSource loads a bundle and its .sig sidecar from local paths.
type FileSource struct {
	BundlePath string
}

func (f FileSource) Fetch() ([]byte, []byte, error) {
	bundle, err := os.ReadFile(f.BundlePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read bundle: %w", err)
	}
	sig, err := ReadSig(f.BundlePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read signature: %w", err)
	}
	return bundle, sig, nil
}

// Loader verifies, compiles, and stores signed policy bundles.
type Loader struct {
	Store  VersionStore
	PubKey ed25519.PublicKey
}

// LoadResult is the outcome of a successful load.
type LoadResult struct {
	Bundle   *Bundle
	Compiled *CompiledPolicy
	Meta     VersionMeta
}

// Load fetches from src, verifies signature, compiles, and stores the version.
func (l *Loader) Load(src Source) (*LoadResult, error) {
	bundleBytes, sig, err := src.Fetch()
	if err != nil {
		return nil, err
	}
	if err := Verify(bundleBytes, sig, l.PubKey); err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	b, err := Parse(bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	compiled, err := Compile(b)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	meta := VersionMeta{
		Version:      b.Version,
		SignedBy:     b.SignedBy,
		AgentScope:   b.AgentScope,
		BundleSHA256: BundleSHA256(bundleBytes),
		Verified:     true,
		State:        StateEnforced,
	}
	if err := l.Store.Put(meta, bundleBytes, sig, compiled); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := l.Store.SetCurrent(b.Version); err != nil {
		return nil, fmt.Errorf("set current: %w", err)
	}
	return &LoadResult{Bundle: b, Compiled: compiled, Meta: meta}, nil
}

// Rollback sets the current enforced version to ver.
func (l *Loader) Rollback(ver int) error {
	stored, err := l.Store.Get(ver)
	if err != nil {
		return err
	}
	if err := l.Store.SetCurrent(ver); err != nil {
		return err
	}
	stored.Meta.State = StateRollback
	return l.Store.Put(stored.Meta, stored.Bundle, stored.Sig, stored.Compiled)
}
