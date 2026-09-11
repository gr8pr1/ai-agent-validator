package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyEffectiveMode(t *testing.T) {
	tests := []struct {
		mode    string
		enabled bool
		want    string
	}{
		{"", false, PolicyModeOff},
		{"", true, PolicyModeShadow},
		{"off", true, PolicyModeOff},
		{"shadow", false, PolicyModeShadow},
		{"enforce", false, PolicyModeEnforce},
	}
	for _, tc := range tests {
		p := PolicyConfig{Mode: tc.mode, Enabled: tc.enabled}
		if got := p.EffectiveMode(); got != tc.want {
			t.Fatalf("mode=%q enabled=%v: got %q want %q", tc.mode, tc.enabled, got, tc.want)
		}
	}
}

func TestLoadPolicyModeValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte(`
mode_a:
  enabled: true
  cgroup_contains: ["slice"]
mode_b:
  enabled: false
policy:
  mode: bogus
  pub_key_path: "policy.pub"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected validation error for bogus policy.mode")
	}
}

func TestLoadDeprecatedEnabledAlias(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte(`
mode_a:
  enabled: true
  cgroup_contains: ["slice"]
mode_b:
  enabled: false
policy:
  enabled: true
  pub_key_path: "policy.pub"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policy.EffectiveMode() != PolicyModeShadow {
		t.Fatalf("got %q", cfg.Policy.EffectiveMode())
	}
}
