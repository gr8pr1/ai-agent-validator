package policy

import "testing"

func TestRuleIDHashStable(t *testing.T) {
	h1 := RuleIDHash("deny-etc-shadow")
	h2 := RuleIDHash("deny-etc-shadow")
	if h1 != h2 {
		t.Fatalf("hash not stable: %x vs %x", h1, h2)
	}
	cp := &CompiledPolicy{
		Live: []CompiledRule{{ID: "deny-etc-shadow", Rationale: "no shadow reads"}},
	}
	if got := LookupRuleID(cp, h1); got != "deny-etc-shadow" {
		t.Fatalf("lookup=%q", got)
	}
	if got := RuleRationale(cp, "deny-etc-shadow"); got != "no shadow reads" {
		t.Fatalf("rationale=%q", got)
	}
}
