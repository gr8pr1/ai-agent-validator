package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPromoteRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	data := `policy_bundle:
  version: 3
  agent_scope: agent
  signed_by: test
  default_action: allow
  fail_direction: open
  rules:
    - id: shadow-public-egress
      rationale: test
      match:
        action: connect
        dest_ip_not_in: ["10.0.0.0/8"]
      decision: deny
      state: shadow
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := PromoteRule(path, "shadow-public-egress", PromoteRuleOptions{
		NewState:    StateEnforced,
		BumpVersion: true,
	}); err != nil {
		t.Fatal(err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != 4 {
		t.Fatalf("version=%d", b.Version)
	}
	if b.Rules[0].State != StateEnforced {
		t.Fatalf("state=%q", b.Rules[0].State)
	}
}

func TestPromoteRuleMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("policy_bundle:\n  version: 1\n  agent_scope: a\n  rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := PromoteRule(path, "missing", PromoteRuleOptions{NewState: StateEnforced})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err=%v", err)
	}
}
