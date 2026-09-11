package policy

import "hash/fnv"

// RuleIDHash returns the FNV-1a hash used in kernel enforcement maps.
func RuleIDHash(id string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return h.Sum32()
}

func findRule(cp *CompiledPolicy, match func(CompiledRule) bool) (CompiledRule, bool) {
	if cp == nil {
		return CompiledRule{}, false
	}
	for _, r := range cp.Live {
		if match(r) {
			return r, true
		}
	}
	for _, r := range cp.Shadow {
		if match(r) {
			return r, true
		}
	}
	return CompiledRule{}, false
}

// RuleByHash returns the compiled rule matching a kernel rule_id_hash.
func RuleByHash(cp *CompiledPolicy, hash uint32) (CompiledRule, bool) {
	return findRule(cp, func(r CompiledRule) bool { return RuleIDHash(r.ID) == hash })
}

// LookupRuleID maps a kernel rule_id_hash back to a compiled rule id.
func LookupRuleID(cp *CompiledPolicy, hash uint32) string {
	if r, ok := RuleByHash(cp, hash); ok {
		return r.ID
	}
	return ""
}

// RuleRationale returns the rationale for a rule id in the compiled policy.
func RuleRationale(cp *CompiledPolicy, ruleID string) string {
	if ruleID == "" {
		return ""
	}
	if r, ok := findRule(cp, func(r CompiledRule) bool { return r.ID == ruleID }); ok {
		return r.Rationale
	}
	return ""
}
