package policy

import (
	"strings"
	"testing"
)

func TestCompileExampleBundle(t *testing.T) {
	b, err := Parse([]byte(validBundle))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Live) != 1 {
		t.Fatalf("live=%d want 1", len(c.Live))
	}
	if len(c.Shadow) != 1 {
		t.Fatalf("shadow=%d want 1", len(c.Shadow))
	}
}

func TestCompileRejectsKill(t *testing.T) {
	yaml := strings.Replace(validBundle, "decision: deny", "decision: kill", 1)
	b, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Compile(b)
	if err == nil || !strings.Contains(err.Error(), "kill") {
		t.Fatalf("expected kill rejection, got %v", err)
	}
}

func TestCompileDenyWinsOverAllow(t *testing.T) {
	yaml := `
policy_bundle:
  version: 2
  agent_scope: "agent:test"
  signed_by: "test"
  rules:
    - id: deny-all-etc
      rationale: "deny etc"
      match:
        action: open
        path_in: ["/etc/*"]
      decision: deny
      state: enforced
    - id: allow-etc-shadow
      rationale: "allow shadow"
      match:
        action: open
        path_in: ["/etc/shadow"]
      decision: allow
      state: enforced
`
	b, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	dec, id, _, ok := EvaluateLive(c.Live, "open", "/etc/shadow")
	if !ok || dec != DecisionDeny || id != "deny-all-etc" {
		t.Fatalf("got dec=%q id=%q ok=%v", dec, id, ok)
	}
}

func TestCompileRejectsAmbiguousDeny(t *testing.T) {
	yaml := `
policy_bundle:
  version: 3
  agent_scope: "agent:test"
  signed_by: "test"
  rules:
    - id: deny-a
      rationale: "a"
      match:
        action: open
        path_in: ["/etc/shadow"]
      decision: deny
      state: enforced
    - id: deny-b
      rationale: "b"
      match:
        action: open
        path_in: ["/etc/shadow"]
      decision: deny
      state: enforced
`
	b, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Compile(b)
	if err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("expected overlap error, got %v", err)
	}
}

func TestPathMatchesGlob(t *testing.T) {
	if !pathMatchesGlob("/etc/shadow", "/etc/shadow") {
		t.Fatal("exact")
	}
	if !pathMatchesGlob("/etc/shadow", "/etc/*") {
		t.Fatal("prefix glob")
	}
	if pathMatchesGlob("/var/log/syslog", "/etc/*") {
		t.Fatal("should not match")
	}
}
