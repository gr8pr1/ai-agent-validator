package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

const (
	defaultKeyPerm  = 0o600
	defaultPubPerm  = 0o644
	sigFileSuffix   = ".sig"
)

// KeyPair holds an Ed25519 signing key pair.
type KeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// Keygen generates a new Ed25519 key pair and writes private/public key files.
func Keygen(keyPath, pubPath string) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	if err := os.WriteFile(keyPath, priv, defaultKeyPerm); err != nil {
		return nil, fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, pub, defaultPubPerm); err != nil {
		return nil, fmt.Errorf("write public key: %w", err)
	}
	return &KeyPair{Private: priv, Public: pub}, nil
}

// LoadPrivateKey reads a private key file.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size %d", len(data))
	}
	return ed25519.PrivateKey(data), nil
}

// LoadPublicKey reads a public key file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size %d", len(data))
	}
	return ed25519.PublicKey(data), nil
}

// Sign signs exact bundle bytes with the private key.
func Sign(bundle []byte, priv ed25519.PrivateKey) []byte {
	return ed25519.Sign(priv, bundle)
}

// Verify checks a signature over exact bundle bytes.
func Verify(bundle, sig []byte, pub ed25519.PublicKey) error {
	if !ed25519.Verify(pub, bundle, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// SigPath returns the sidecar signature path for a bundle file.
func SigPath(bundlePath string) string {
	return bundlePath + sigFileSuffix
}

// WriteSig writes a base64-encoded detached signature sidecar.
func WriteSig(bundlePath string, sig []byte) error {
	enc := base64.StdEncoding.EncodeToString(sig)
	return os.WriteFile(SigPath(bundlePath), []byte(enc+"\n"), defaultKeyPerm)
}

// ReadSig reads a base64-encoded detached signature sidecar.
func ReadSig(bundlePath string) ([]byte, error) {
	data, err := os.ReadFile(SigPath(bundlePath))
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	return sig, nil
}

// SignFile signs a bundle file and writes the .sig sidecar.
func SignFile(bundlePath string, priv ed25519.PrivateKey) error {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return err
	}
	sig := Sign(data, priv)
	return WriteSig(bundlePath, sig)
}

// VerifyFile verifies a bundle file against its .sig sidecar.
func VerifyFile(bundlePath string, pub ed25519.PublicKey) error {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return err
	}
	sig, err := ReadSig(bundlePath)
	if err != nil {
		return err
	}
	return Verify(data, sig, pub)
}
