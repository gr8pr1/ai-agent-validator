// Package config loads agent configuration from YAML, applies defaults, and
// validates it.
package config

import (
	"fmt"
	"os"

	yaml "go.yaml.in/yaml/v2"
)

// Config is the top-level agent configuration.
type Config struct {
	LogLevel  string       `yaml:"log_level"`  // debug|info|warn|error
	LogFormat string       `yaml:"log_format"` // text|json
	ModeA     ModeAConfig  `yaml:"mode_a"`
	ModeB     ModeBConfig  `yaml:"mode_b"`
	Report    ReportConfig `yaml:"report"`
	Debug     DebugConfig  `yaml:"debug"`
}

// ModeAConfig controls controlled-spawn cgroup enrollment.
type ModeAConfig struct {
	Enabled        bool     `yaml:"enabled"`
	CgroupContains []string `yaml:"cgroup_contains"` // substrings matched against the cgroup-v2 path
	DefaultAgentID string   `yaml:"default_agent_id"`
}

// ModeBConfig controls exec-time fingerprint enrollment.
type ModeBConfig struct {
	Enabled          bool   `yaml:"enabled"`
	FingerprintsPath string `yaml:"fingerprints_path"`
}

// ReportConfig controls the observation/enrollment output.
type ReportConfig struct {
	Format      string `yaml:"format"`       // text|json
	AuditLog    string `yaml:"audit_log"`    // path; empty disables file audit
	AllEvents   bool   `yaml:"all_events"`   // report untagged events too (noisy)
	SnapshotSec int    `yaml:"snapshot_sec"` // periodic snapshot interval; 0 disables
}

// DebugConfig controls the debug surface.
type DebugConfig struct {
	Enabled  bool   `yaml:"enabled"`
	HTTPAddr string `yaml:"http_addr"`
}

// Default returns a config with sane defaults.
func Default() Config {
	return Config{
		LogLevel:  "info",
		LogFormat: "text",
		ModeA: ModeAConfig{
			Enabled:        true,
			CgroupContains: []string{"ai-agents.slice"},
			DefaultAgentID: "agent",
		},
		ModeB: ModeBConfig{
			Enabled:          true,
			FingerprintsPath: "fingerprints.yaml",
		},
		Report: ReportConfig{
			Format:      "text",
			AllEvents:   false,
			SnapshotSec: 30,
		},
		Debug: DebugConfig{
			Enabled:  false,
			HTTPAddr: "127.0.0.1:9230",
		},
	}
}

// Load reads YAML from path over the defaults. A missing path yields defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	switch c.Report.Format {
	case "text", "json":
	default:
		return fmt.Errorf("report.format must be text|json, got %q", c.Report.Format)
	}
	if !c.ModeA.Enabled && !c.ModeB.Enabled {
		return fmt.Errorf("at least one of mode_a/mode_b must be enabled")
	}
	return nil
}
