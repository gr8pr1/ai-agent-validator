package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	storeDirPerm   = 0o700
	storeFilePerm  = 0o600
	manifestName   = "manifest.json"
	currentName    = "current"
	versionsDir    = "versions"
)

// VersionMeta records metadata for one stored policy version.
type VersionMeta struct {
	Version     int       `json:"version"`
	SignedBy    string    `json:"signed_by"`
	AgentScope  string    `json:"agent_scope"`
	LoadedAt    time.Time `json:"loaded_at"`
	BundleSHA256 string   `json:"bundle_sha256"`
	Verified    bool      `json:"verified"`
	State       string    `json:"state"` // enforced|shadow|rollback
}

// StoredVersion is a bundle + signature + metadata retrieved from the store.
type StoredVersion struct {
	Meta     VersionMeta
	Bundle   []byte
	Sig      []byte
	Compiled *CompiledPolicy
}

// VersionStore persists signed policy versions.
type VersionStore interface {
	Put(meta VersionMeta, bundle, sig []byte, compiled *CompiledPolicy) error
	Get(version int) (*StoredVersion, error)
	List() ([]VersionMeta, error)
	Current() (int, error)
	SetCurrent(version int) error
}

type fileStore struct {
	root string
}

// OpenStore opens or creates a file-backed version store at root.
func OpenStore(root string) (VersionStore, error) {
	if err := os.MkdirAll(filepath.Join(root, versionsDir), storeDirPerm); err != nil {
		return nil, err
	}
	return &fileStore{root: root}, nil
}

func (s *fileStore) versionDir(ver int) string {
	return filepath.Join(s.root, versionsDir, fmt.Sprintf("%d", ver))
}

func (s *fileStore) Put(meta VersionMeta, bundle, sig []byte, compiled *CompiledPolicy) error {
	dir := s.versionDir(meta.Version)
	if err := os.MkdirAll(dir, storeDirPerm); err != nil {
		return err
	}
	if meta.BundleSHA256 == "" {
		sum := sha256.Sum256(bundle)
		meta.BundleSHA256 = hex.EncodeToString(sum[:])
	}
	if meta.LoadedAt.IsZero() {
		meta.LoadedAt = time.Now().UTC()
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.yaml"), bundle, storeFilePerm); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.yaml.sig"), sig, storeFilePerm); err != nil {
		return err
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), metaBytes, storeFilePerm); err != nil {
		return err
	}
	if compiled != nil {
		compBytes, err := json.MarshalIndent(compiled, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "compiled.json"), compBytes, storeFilePerm); err != nil {
			return err
		}
	}
	return s.updateManifest(meta)
}

func (s *fileStore) updateManifest(meta VersionMeta) error {
	list, err := s.List()
	if err != nil {
		return err
	}
	found := false
	for i := range list {
		if list[i].Version == meta.Version {
			list[i] = meta
			found = true
			break
		}
	}
	if !found {
		list = append(list, meta)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Version < list[j].Version })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.root, manifestName), data, storeFilePerm)
}

func (s *fileStore) Get(version int) (*StoredVersion, error) {
	dir := s.versionDir(version)
	metaBytes, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, fmt.Errorf("version %d: %w", version, err)
	}
	var meta VersionMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, err
	}
	bundle, err := os.ReadFile(filepath.Join(dir, "bundle.yaml"))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, "bundle.yaml.sig"))
	if err != nil {
		return nil, err
	}
	out := &StoredVersion{Meta: meta, Bundle: bundle, Sig: sig}
	compPath := filepath.Join(dir, "compiled.json")
	if compBytes, err := os.ReadFile(compPath); err == nil {
		var compiled CompiledPolicy
		if err := json.Unmarshal(compBytes, &compiled); err == nil {
			out.Compiled = &compiled
		}
	}
	return out, nil
}

func (s *fileStore) List() ([]VersionMeta, error) {
	path := filepath.Join(s.root, manifestName)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var list []VersionMeta
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *fileStore) Current() (int, error) {
	data, err := os.ReadFile(filepath.Join(s.root, currentName))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var ver int
	if _, err := fmt.Sscanf(string(data), "%d", &ver); err != nil {
		return 0, err
	}
	return ver, nil
}

func (s *fileStore) SetCurrent(version int) error {
	if version > 0 {
		if _, err := s.Get(version); err != nil {
			return fmt.Errorf("set current: %w", err)
		}
	}
	return os.WriteFile(filepath.Join(s.root, currentName), []byte(fmt.Sprintf("%d\n", version)), storeFilePerm)
}

// BundleSHA256 returns the hex sha256 of bundle bytes.
func BundleSHA256(bundle []byte) string {
	sum := sha256.Sum256(bundle)
	return hex.EncodeToString(sum[:])
}
