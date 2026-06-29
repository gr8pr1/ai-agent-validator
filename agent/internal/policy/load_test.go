package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validBundle = `
policy_bundle:
  version: 1
  agent_scope: "agent:test"
  signed_by: "test"
  default_action: allow
  fail_direction: open
  rules:
    - id: deny-shadow
      rationale: "test shadow"
      match:
        action: connect
        dest_port_not_in: [443]
      decision: deny
      state: shadow
    - id: deny-open
      rationale: "deny shadow reads"
      match:
        action: open
        path_in: ["/etc/shadow"]
      decision: deny
      state: enforced
`

func TestLoadValidBundle(t *testing.T) {
	b, err := Parse([]byte(validBundle))
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != 1 || b.AgentScope != "agent:test" {
		t.Fatalf("unexpected bundle: %+v", b)
	}
}

func TestLoadRejectsDuplicateID(t *testing.T) {
	yaml := strings.Replace(validBundle, "deny-open", "deny-shadow", 1)
	_, err := Parse([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("expected duplicate id error, got %v", err)
	}
}

func TestLoadRejectsUnknownAction(t *testing.T) {
	yaml := strings.Replace(validBundle, "action: open", "action: frobnicate", 1)
	_, err := Parse([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "unknown action") {
		t.Fatalf("expected unknown action error, got %v", err)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(validBundle), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Rules) != 2 {
		t.Fatalf("rules=%d", len(b.Rules))
	}
}
