package policy

import (
	"testing"
)

func TestEvaluateActionsPathDeny(t *testing.T) {
	rules := []CompiledRule{{
		ID: "deny-etc", Rationale: "no etc", Decision: DecisionDeny,
		Action: "open", PathIn: []string{"/etc/*"}, Specificity: 5,
	}}
	dec, id, _, ok := EvaluateActions(rules, ActionInput{Action: "open", Path: "/etc/shadow"})
	if !ok || dec != DecisionDeny || id != "deny-etc" {
		t.Fatalf("got dec=%q id=%q ok=%v", dec, id, ok)
	}
}

func TestEvaluateActionsConnectPort(t *testing.T) {
	rules := []CompiledRule{{
		ID: "deny-port", Rationale: "bad port", Decision: DecisionDeny,
		Action: "connect", DestPortNotIn: []uint16{443, 80}, Specificity: 16,
	}}
	dec, _, _, ok := EvaluateActions(rules, ActionInput{
		Action: "connect", DestIP: "10.0.0.1", DestPort: 9999,
	})
	if !ok || dec != DecisionDeny {
		t.Fatalf("expected deny on port 9999, got %q ok=%v", dec, ok)
	}
	_, _, _, ok = EvaluateActions(rules, ActionInput{
		Action: "connect", DestIP: "10.0.0.1", DestPort: 443,
	})
	if ok {
		t.Fatal("port 443 should not match deny")
	}
}

func TestEvaluateActionsDestIP(t *testing.T) {
	rules := []CompiledRule{{
		ID: "deny-egress", Rationale: "no public", Decision: DecisionDeny,
		Action: "connect", DestIPNotIn: []string{"10.0.0.0/8"}, Specificity: 8,
	}}
	dec, _, _, ok := EvaluateActions(rules, ActionInput{
		Action: "connect", DestIP: "8.8.8.8", DestPort: 443,
	})
	if !ok || dec != DecisionDeny {
		t.Fatalf("expected deny on public IP, got %q ok=%v", dec, ok)
	}
	_, _, _, ok = EvaluateActions(rules, ActionInput{
		Action: "connect", DestIP: "10.1.2.3", DestPort: 443,
	})
	if ok {
		t.Fatal("10.x should not match deny")
	}
}

func TestEvaluateActionsWriteIntent(t *testing.T) {
	rules := []CompiledRule{{
		ID: "deny-write", Rationale: "no writes", Decision: DecisionDeny,
		Action: "write", PathIn: []string{"/etc/*"}, Specificity: 5,
	}}
	dec, _, _, ok := EvaluateActions(rules, ActionInput{
		Action: "open", Path: "/etc/hosts", WriteIntent: true,
	})
	if !ok || dec != DecisionDeny {
		t.Fatalf("write rule should match write-intent open, got %q ok=%v", dec, ok)
	}
	_, _, _, ok = EvaluateActions(rules, ActionInput{
		Action: "open", Path: "/etc/hosts", WriteIntent: false,
	})
	if ok {
		t.Fatal("read-only open should not match write rule")
	}
}

func TestEvaluateActionsUIDBinaryCgroup(t *testing.T) {
	uid := uint32(1000)
	uidPtr := &uid
	rules := []CompiledRule{{
		ID: "scoped", Rationale: "scoped", Decision: DecisionDeny,
		Action: "open", PathIn: []string{"/tmp/*"}, UID: &uid,
		Binary: "/usr/bin/curl", Cgroup: "ai-agents", Specificity: 32,
	}}
	in := ActionInput{
		Action: "open", Path: "/tmp/x", UID: uidPtr,
		Binary: "/usr/bin/curl", Cgroup: "/system.slice/ai-agents.slice/job",
	}
	dec, _, _, ok := EvaluateActions(rules, in)
	if !ok || dec != DecisionDeny {
		t.Fatalf("expected match, got %q ok=%v", dec, ok)
	}
	badUID := uint32(1001)
	in.UID = &badUID
	_, _, _, ok = EvaluateActions(rules, in)
	if ok {
		t.Fatal("uid mismatch should not match")
	}
}

func TestEvaluateActionsUIDZero(t *testing.T) {
	root := uint32(0)
	rules := []CompiledRule{{
		ID: "root-only", Rationale: "root", Decision: DecisionDeny,
		Action: "open", PathIn: []string{"/etc/*"}, UID: &root, Specificity: 32,
	}}
	dec, _, _, ok := EvaluateActions(rules, ActionInput{
		Action: "open", Path: "/etc/shadow", UID: &root,
	})
	if !ok || dec != DecisionDeny {
		t.Fatalf("uid 0 should match, got %q ok=%v", dec, ok)
	}
}

func TestEvaluateActionsRenameDestPath(t *testing.T) {
	rules := []CompiledRule{{
		ID: "deny-etc", Rationale: "no etc", Decision: DecisionDeny,
		Action: "rename", PathIn: []string{"/etc/*"}, Specificity: 5,
	}}
	dec, id, _, ok := EvaluateActions(rules, ActionInput{
		Action: "rename", Path: "/tmp/x", NewPath: "/etc/hosts",
	})
	if !ok || dec != DecisionDeny || id != "deny-etc" {
		t.Fatalf("rename into /etc should match, got dec=%q id=%q ok=%v", dec, id, ok)
	}
	_, _, _, ok = EvaluateActions(rules, ActionInput{
		Action: "rename", Path: "/var/log/x", NewPath: "/var/log/y",
	})
	if ok {
		t.Fatal("rename outside /etc should not match")
	}
}

func TestEvaluateShadowAndLive(t *testing.T) {
	cp := &CompiledPolicy{
		Shadow: []CompiledRule{{
			ID: "shadow-rule", Rationale: "shadow", Decision: DecisionDeny,
			Action: "connect", DestPortNotIn: []uint16{443}, Specificity: 16,
		}},
		Live: []CompiledRule{{
			ID: "live-rule", Rationale: "live", Decision: DecisionDeny,
			Action: "open", PathIn: []string{"/etc/*"}, Specificity: 5,
		}},
	}
	in := ActionInput{Action: "connect", DestIP: "1.2.3.4", DestPort: 22}
	hits := EvaluateShadowAndLive(cp, in)
	if len(hits) != 1 || hits[0].Source != ShadowSourceShadow || hits[0].RuleID != "shadow-rule" {
		t.Fatalf("shadow hit: %+v", hits)
	}
	in = ActionInput{Action: "open", Path: "/etc/shadow"}
	hits = EvaluateShadowAndLive(cp, in)
	if len(hits) != 1 || hits[0].Source != ShadowSourceLivePreview {
		t.Fatalf("live preview hit: %+v", hits)
	}
}

func TestScopeMatches(t *testing.T) {
	if !ScopeMatches("agent:ci-runner", "agent:ci-runner") {
		t.Fatal("exact match")
	}
	if !ScopeMatches("ci-runner", "agent:ci-runner") {
		t.Fatal("prefix strip match")
	}
	if ScopeMatches("claude-code", "agent:ci-runner") {
		t.Fatal("should not match different ids")
	}
}
