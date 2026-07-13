package policy

import (
	"net"
	"strings"
)

// ShadowSource labels which rule set produced a shadow verdict.
const (
	ShadowSourceShadow      = "shadow"
	ShadowSourceLivePreview = "live_preview"
)

// ActionInput is the runtime context for shadow evaluation (P2).
type ActionInput struct {
	Action      string
	Path        string
	NewPath     string
	DestIP      string
	DestPort    uint16
	WriteIntent bool
	UID         *uint32 // nil when UID unavailable; supports uid 0
	Binary      string
	Cgroup      string
}

// ShadowHit is one would-have-blocked match.
type ShadowHit struct {
	Source    string
	RuleID    string
	Decision  string
	Rationale string
}

// ScopeMatches reports whether agentID is in scope for the bundle agent_scope.
// Exact equality after optional "agent:" prefix strip (decision 4A).
func ScopeMatches(agentID, agentScope string) bool {
	if agentScope == "" || agentID == "" {
		return false
	}
	return normalizeScopeID(agentID) == normalizeScopeID(agentScope)
}

func normalizeScopeID(id string) string {
	return strings.TrimPrefix(id, "agent:")
}

// EvaluateActions returns the winning decision for a rule set.
func EvaluateActions(rules []CompiledRule, in ActionInput) (decision, ruleID, rationale string, matched bool) {
	var best *CompiledRule
	for i := range rules {
		r := &rules[i]
		if !ruleMatchesAction(r, in) {
			continue
		}
		if !ruleMatchesPredicates(r, in) {
			continue
		}
		if best == nil {
			best = r
			continue
		}
		if r.Decision == DecisionDeny && best.Decision == DecisionAllow {
			best = r
			continue
		}
		if r.Decision == best.Decision && r.Specificity > best.Specificity {
			best = r
		}
	}
	if best == nil {
		return "", "", "", false
	}
	return best.Decision, best.ID, best.Rationale, true
}

// EvaluateShadowAndLive returns deny hits from shadow and live rule sets.
func EvaluateShadowAndLive(cp *CompiledPolicy, in ActionInput) []ShadowHit {
	if cp == nil {
		return nil
	}
	var hits []ShadowHit
	if dec, id, rat, ok := EvaluateActions(cp.Shadow, in); ok && dec == DecisionDeny {
		hits = append(hits, ShadowHit{
			Source: ShadowSourceShadow, RuleID: id, Decision: dec, Rationale: rat,
		})
	}
	if dec, id, rat, ok := EvaluateActions(cp.Live, in); ok && dec == DecisionDeny {
		hits = append(hits, ShadowHit{
			Source: ShadowSourceLivePreview, RuleID: id, Decision: dec, Rationale: rat,
		})
	}
	return hits
}

func ruleMatchesAction(r *CompiledRule, in ActionInput) bool {
	if r.Action == in.Action {
		return true
	}
	if in.Action == "open" && r.Action == "write" && in.WriteIntent {
		return true
	}
	return false
}

func ruleMatchesPredicates(r *CompiledRule, in ActionInput) bool {
	if len(r.PathIn) > 0 || len(r.PathNotIn) > 0 {
		if !ruleMatchesPaths(r, in) {
			return false
		}
	}
	if len(r.DestIPIn) > 0 || len(r.DestIPNotIn) > 0 {
		if in.DestIP == "" || !ruleMatchesDestIP(r, in.DestIP) {
			return false
		}
	}
	if len(r.DestPortIn) > 0 || len(r.DestPortNotIn) > 0 {
		if !ruleMatchesDestPort(r, in.DestPort) {
			return false
		}
	}
	if r.UID != nil {
		if in.UID == nil || *r.UID != *in.UID {
			return false
		}
	}
	if r.Binary != "" {
		if in.Binary == "" || r.Binary != in.Binary {
			return false
		}
	}
	if r.Cgroup != "" {
		if in.Cgroup == "" || !strings.Contains(in.Cgroup, r.Cgroup) {
			return false
		}
	}
	return true
}

func ruleMatchesPaths(r *CompiledRule, in ActionInput) bool {
	if in.Action == "rename" {
		return ruleMatchesPath(r, in.Path) || ruleMatchesPath(r, in.NewPath)
	}
	path := in.Path
	if path == "" {
		path = in.NewPath
	}
	return ruleMatchesPath(r, path)
}

func ruleMatchesDestIP(r *CompiledRule, dest string) bool {
	ip := net.ParseIP(dest)
	if ip == nil {
		return false
	}
	for _, cidr := range r.DestIPNotIn {
		if ipInCIDR(ip, cidr) {
			return false
		}
	}
	if len(r.DestIPIn) == 0 {
		return true
	}
	for _, cidr := range r.DestIPIn {
		if ipInCIDR(ip, cidr) {
			return true
		}
	}
	return false
}

func ipInCIDR(ip net.IP, cidr string) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err == nil {
		return n.Contains(ip)
	}
	return ip.Equal(net.ParseIP(cidr))
}

func ruleMatchesDestPort(r *CompiledRule, port uint16) bool {
	for _, p := range r.DestPortNotIn {
		if p == port {
			return false
		}
	}
	if len(r.DestPortIn) == 0 {
		return true
	}
	for _, p := range r.DestPortIn {
		if p == port {
			return true
		}
	}
	return false
}
