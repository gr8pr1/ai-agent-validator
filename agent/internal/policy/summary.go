package policy

import (
	"fmt"
	"strings"
)

// FormatCompiledSummary prints which compiled rules are live (kernel) vs shadow.
func FormatCompiledSummary(cp *CompiledPolicy) string {
	if cp == nil {
		return "compiled policy: (nil)\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "policy v%d scope=%q live=%d shadow=%d\n", cp.Version, cp.AgentScope, len(cp.Live), len(cp.Shadow))
	if len(cp.Live) > 0 {
		fmt.Fprintf(&b, "  live (kernel): %s\n", joinRuleIDs(cp.Live))
	} else {
		b.WriteString("  live (kernel): (none — nothing will be enforced in the kernel)\n")
	}
	if len(cp.Shadow) > 0 {
		fmt.Fprintf(&b, "  shadow (userspace): %s\n", joinRuleIDs(cp.Shadow))
	}
	return b.String()
}

func joinRuleIDs(rules []CompiledRule) string {
	ids := make([]string, len(rules))
	seen := make(map[string]struct{}, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
		seen[r.ID] = struct{}{}
	}
	return strings.Join(ids, ", ")
}
