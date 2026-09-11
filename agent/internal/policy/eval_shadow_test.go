package policy

import "testing"

func TestEvaluateShadowOnlyIgnoresLive(t *testing.T) {
	cp := &CompiledPolicy{
		Shadow: []CompiledRule{},
		Live: []CompiledRule{{
			ID: "deny-live", Rationale: "live deny", Decision: DecisionDeny,
			Action: "open", PathIn: []string{"/etc/shadow"}, Specificity: 12,
		}},
	}
	in := ActionInput{Action: "open", Path: "/etc/shadow"}
	if hits := EvaluateShadowOnly(cp, in); len(hits) != 0 {
		t.Fatalf("expected no hits, got %+v", hits)
	}
	if hits := EvaluateShadowAndLive(cp, in); len(hits) != 1 || hits[0].Source != ShadowSourceLivePreview {
		t.Fatalf("live preview expected, got %+v", hits)
	}
}
