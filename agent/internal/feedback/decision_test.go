package feedback

import (
	"testing"
	"time"
)

func TestNewDecisionOpen(t *testing.T) {
	at := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	d := NewDecision(at, 42, "open", "/etc/shadow", "agent", "deny-etc-shadow", "no shadow reads", 3)
	if d.Decision != DecisionDenied || d.Retry != RetryDoNot {
		t.Fatalf("decision=%q retry=%q", d.Decision, d.Retry)
	}
	if d.MatchedRule != "deny-etc-shadow" || d.Target != "/etc/shadow" {
		t.Fatalf("rule=%q target=%q", d.MatchedRule, d.Target)
	}
	if !d.Time.Equal(at) {
		t.Fatalf("time=%v want=%v", d.Time, at)
	}
}
