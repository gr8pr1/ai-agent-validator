package feedback

import (
	"testing"
)

func TestNewDecisionOpen(t *testing.T) {
	d := NewDecision(1_000_000_000, 42, "open", "/etc/shadow", "agent", "deny-etc-shadow", "no shadow reads", 3)

	if d.Decision != DecisionDenied || d.Retry != RetryDoNot {
		t.Fatalf("decision=%q retry=%q", d.Decision, d.Retry)
	}
	if d.Action != "open" || d.Target != "/etc/shadow" {
		t.Fatalf("action=%q target=%q", d.Action, d.Target)
	}
	if d.MatchedRule != "deny-etc-shadow" || d.Reason != "no shadow reads" {
		t.Fatalf("rule=%q reason=%q", d.MatchedRule, d.Reason)
	}
	if d.AgentID != "agent" || d.PolicyVersion != 3 {
		t.Fatalf("agent=%q version=%d", d.AgentID, d.PolicyVersion)
	}
}

func TestHubRecordForAgent(t *testing.T) {
	h, err := NewHub("", 2)
	if err != nil {
		t.Fatal(err)
	}
	h.Record(Decision{AgentID: "a", MatchedRule: "r1"})
	h.Record(Decision{AgentID: "a", MatchedRule: "r2"})
	h.Record(Decision{AgentID: "a", MatchedRule: "r3"})

	got := h.ForAgent("a")
	if len(got) != 2 {
		t.Fatalf("len=%d want 2 (ring)", len(got))
	}
	if got[0].MatchedRule != "r2" || got[1].MatchedRule != "r3" {
		t.Fatalf("ring=%v", got)
	}
}
