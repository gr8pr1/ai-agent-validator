package policy

import (
	"fmt"
	"net"
	"strings"
)

// CompiledPolicy is the map-ready output of the compiler.
type CompiledPolicy struct {
	Version       int            `json:"version"`
	AgentScope    string         `json:"agent_scope"`
	SignedBy      string         `json:"signed_by"`
	DefaultAction string         `json:"default_action"`
	FailDirection string         `json:"fail_direction"`
	Live          []CompiledRule `json:"live"`
	Shadow        []CompiledRule `json:"shadow"`
}

// CompiledRule is one lowered, evaluatable rule entry.
type CompiledRule struct {
	ID          string   `json:"id"`
	Rationale   string   `json:"rationale"`
	Decision    string   `json:"decision"`
	Action      string   `json:"action"`
	PathIn      []string `json:"path_in,omitempty"`
	PathNotIn   []string `json:"path_not_in,omitempty"`
	DestIPIn    []string `json:"dest_ip_in,omitempty"`
	DestIPNotIn []string `json:"dest_ip_not_in,omitempty"`
	DestPortIn  []uint16 `json:"dest_port_in,omitempty"`
	DestPortNotIn []uint16 `json:"dest_port_not_in,omitempty"`
	UID         *uint32  `json:"uid,omitempty"`
	Binary      string   `json:"binary,omitempty"`
	Cgroup      string   `json:"cgroup,omitempty"`
	Specificity int      `json:"specificity"`
}

// Compile lowers a validated bundle to a CompiledPolicy.
func Compile(b *Bundle) (*CompiledPolicy, error) {
	out := &CompiledPolicy{
		Version:       b.Version,
		AgentScope:    b.AgentScope,
		SignedBy:      b.SignedBy,
		DefaultAction: b.DefaultAction,
		FailDirection: b.FailDirection,
	}

	for _, r := range b.Rules {
		if r.Decision == DecisionKill {
			return nil, fmt.Errorf("rule %q: decision kill is planned for P3+ and not supported in P1", r.ID)
		}
		if r.State == StateRetired || r.State == StateDraft || r.State == StateRollback {
			continue
		}
		entries, err := lowerRule(r)
		if err != nil {
			return nil, err
		}
		switch {
		case IsLiveState(r.State):
			out.Live = append(out.Live, entries...)
		case IsShadowState(r.State):
			out.Shadow = append(out.Shadow, entries...)
		}
	}

	if err := resolveConflicts(out.Live, "enforced"); err != nil {
		return nil, err
	}
	if err := resolveConflicts(out.Shadow, "shadow"); err != nil {
		return nil, err
	}
	return out, nil
}

func lowerRule(r Rule) ([]CompiledRule, error) {
	actions := r.Match.Actions()
	if len(actions) == 0 {
		return nil, fmt.Errorf("rule %q: match.action is required", r.ID)
	}
	spec := matchSpecificity(r.Match)
	out := make([]CompiledRule, 0, len(actions))
	for _, act := range actions {
		out = append(out, CompiledRule{
			ID:            r.ID,
			Rationale:     strings.TrimSpace(r.Rationale),
			Decision:      r.Decision,
			Action:        act,
			PathIn:        append([]string(nil), r.Match.PathIn...),
			PathNotIn:     append([]string(nil), r.Match.PathNotIn...),
			DestIPIn:      append([]string(nil), r.Match.DestIPIn...),
			DestIPNotIn:   append([]string(nil), r.Match.DestIPNotIn...),
			DestPortIn:    append([]uint16(nil), r.Match.DestPortIn...),
			DestPortNotIn: append([]uint16(nil), r.Match.DestPortNotIn...),
			UID:           r.Match.UID,
			Binary:        r.Match.Binary,
			Cgroup:        r.Match.Cgroup,
			Specificity:   spec,
		})
	}
	return out, nil
}

func matchSpecificity(m Match) int {
	spec := 0
	for _, p := range append(m.PathIn, m.PathNotIn...) {
		spec = max(spec, pathSpecificity(p))
	}
	for _, cidr := range append(m.DestIPIn, m.DestIPNotIn...) {
		spec = max(spec, cidrSpecificity(cidr))
	}
	if len(m.DestPortIn) > 0 || len(m.DestPortNotIn) > 0 {
		spec = max(spec, 16)
	}
	if m.UID != nil {
		spec = max(spec, 32)
	}
	if m.Binary != "" {
		spec = max(spec, len(m.Binary))
	}
	if m.Cgroup != "" {
		spec = max(spec, len(m.Cgroup))
	}
	if spec == 0 {
		spec = 1
	}
	return spec
}

func pathSpecificity(p string) int {
	if p == "" {
		return 0
	}
	if idx := strings.Index(p, "*"); idx >= 0 {
		return idx
	}
	return len(p)
}

func cidrSpecificity(cidr string) int {
	_, n, err := net.ParseCIDR(cidr)
	if err == nil {
		ones, _ := n.Mask.Size()
		return ones
	}
	if ip := net.ParseIP(cidr); ip != nil {
		if ip.To4() != nil {
			return 32
		}
		return 128
	}
	return 0
}

type conflictKey struct {
	action      string
	specificity int
}

func resolveConflicts(rules []CompiledRule, label string) error {
	// Group by action+specificity; at same level deny must not conflict with another deny
	// on overlapping criteria, and allow vs deny is OK (deny wins at eval time).
	byKey := make(map[conflictKey][]CompiledRule)
	for _, r := range rules {
		k := conflictKey{action: r.Action, specificity: r.Specificity}
		byKey[k] = append(byKey[k], r)
	}
	for k, group := range byKey {
		if len(group) < 2 {
			continue
		}
		for i := 0; i < len(group); i++ {
			for j := i + 1; j < len(group); j++ {
				a, b := group[i], group[j]
				if a.Decision != b.Decision {
					continue // deny wins over allow at runtime
				}
				if rulesOverlap(a, b) {
					return fmt.Errorf("%s rules %q and %q overlap at action=%q specificity=%d with same decision %q",
						label, a.ID, b.ID, k.action, k.specificity, a.Decision)
				}
			}
		}
	}
	return nil
}

func rulesOverlap(a, b CompiledRule) bool {
	if !sliceOverlap(a.PathIn, b.PathIn) && len(a.PathIn) > 0 && len(b.PathIn) > 0 {
		return false
	}
	if !sliceOverlap(a.DestIPIn, b.DestIPIn) && len(a.DestIPIn) > 0 && len(b.DestIPIn) > 0 {
		return false
	}
	if !sliceOverlap(a.DestIPNotIn, b.DestIPNotIn) && len(a.DestIPNotIn) > 0 && len(b.DestIPNotIn) > 0 {
		return false
	}
	if !portOverlap(a.DestPortIn, b.DestPortIn) && len(a.DestPortIn) > 0 && len(b.DestPortIn) > 0 {
		return false
	}
	if !portOverlap(a.DestPortNotIn, b.DestPortNotIn) && len(a.DestPortNotIn) > 0 && len(b.DestPortNotIn) > 0 {
		return false
	}
	if a.Binary != "" && b.Binary != "" && a.Binary != b.Binary {
		return false
	}
	if a.Cgroup != "" && b.Cgroup != "" && a.Cgroup != b.Cgroup {
		return false
	}
	if a.UID != nil && b.UID != nil && *a.UID != *b.UID {
		return false
	}
	return true
}

func sliceOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, x := range a {
		for _, y := range b {
			if pathsOverlap(x, y) || pathsOverlap(y, x) {
				return true
			}
		}
	}
	return false
}

func pathsOverlap(a, b string) bool {
	if a == b {
		return true
	}
	pa := strings.TrimSuffix(strings.TrimSuffix(a, "/*"), "*")
	pb := strings.TrimSuffix(strings.TrimSuffix(b, "/*"), "*")
	if pa == "" || pb == "" {
		return true
	}
	return strings.HasPrefix(a, pb) || strings.HasPrefix(b, pa) ||
		strings.HasPrefix(pa, pb) || strings.HasPrefix(pb, pa)
}

func portOverlap(a, b []uint16) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	set := make(map[uint16]struct{}, len(a))
	for _, p := range a {
		set[p] = struct{}{}
	}
	for _, p := range b {
		if _, ok := set[p]; ok {
			return true
		}
	}
	return false
}

// EvaluateLive returns the winning decision for a live rule set (for tests / future P3).
// deny beats allow; higher specificity wins among same decision.
func EvaluateLive(rules []CompiledRule, action string, path string) (decision, ruleID, rationale string, matched bool) {
	return EvaluateActions(rules, ActionInput{Action: action, Path: path})
}

func ruleMatchesPath(r *CompiledRule, path string) bool {
	if len(r.PathIn) == 0 && len(r.PathNotIn) == 0 {
		return true
	}
	for _, p := range r.PathNotIn {
		if pathMatchesGlob(path, p) {
			return false
		}
	}
	if len(r.PathIn) == 0 {
		return true
	}
	for _, p := range r.PathIn {
		if pathMatchesGlob(path, p) {
			return true
		}
	}
	return false
}

func pathMatchesGlob(path, pattern string) bool {
	if pattern == path {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	}
	if strings.Contains(pattern, "*") {
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			return strings.HasPrefix(path, parts[0]) && strings.HasSuffix(path, parts[1])
		}
	}
	return false
}
