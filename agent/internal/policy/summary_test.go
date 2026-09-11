package policy

import (
	"strings"
	"testing"
)

func TestFormatCompiledSummary(t *testing.T) {
	cp := &CompiledPolicy{
		Version:    1,
		AgentScope: "agent",
		Live: []CompiledRule{
			{ID: "deny-etc-shadow"},
			{ID: "deny-public-egress"},
		},
		Shadow: []CompiledRule{
			{ID: "shadow-unusual-port"},
		},
	}
	out := FormatCompiledSummary(cp)
	for _, want := range []string{
		"live (kernel): deny-etc-shadow",
		"deny-public-egress",
		"shadow (userspace): shadow-unusual-port",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing %q:\n%s", want, out)
		}
	}
}
