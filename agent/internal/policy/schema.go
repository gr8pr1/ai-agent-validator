// Package policy implements the P1 policy schema, compiler, signing, and loader.
package policy

import "strings"

// Valid action tokens for match.action (supports | alternation in YAML).
var validActions = map[string]struct{}{
	"connect": {},
	"open":    {},
	"write":   {},
	"unlink":  {},
	"rename":  {},
	"exec":    {},
}

// Valid rule decisions.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
	DecisionKill  = "kill"
)

// Valid rule lifecycle states.
const (
	StateDraft     = "draft"
	StateShadow    = "shadow"
	StateEnforced  = "enforced"
	StateRetired   = "retired"
	StateRollback  = "rollback"
)

// Valid bundle-level defaults.
const (
	DefaultActionAllow = "allow"
	DefaultActionDeny  = "deny"

	FailDirectionOpen   = "open"
	FailDirectionClosed = "closed"
)

// Document is the top-level YAML envelope.
type Document struct {
	PolicyBundle Bundle `yaml:"policy_bundle"`
}

// Bundle is a signed, versioned policy bundle (architecture §8).
type Bundle struct {
	Version        int    `yaml:"version"`
	AgentScope     string `yaml:"agent_scope"`
	SignedBy       string `yaml:"signed_by"`
	DefaultAction  string `yaml:"default_action"`
	FailDirection  string `yaml:"fail_direction"`
	Rules          []Rule `yaml:"rules"`
}

// Rule is one allow/deny rule in a bundle.
type Rule struct {
	ID        string `yaml:"id"`
	Rationale string `yaml:"rationale"`
	Match     Match  `yaml:"match"`
	Decision  string `yaml:"decision"`
	State     string `yaml:"state"`
}

// Match is the closed vocabulary of kernel-evaluable predicates.
type Match struct {
	Action          string   `yaml:"action"`
	PathIn          []string `yaml:"path_in"`
	PathNotIn       []string `yaml:"path_not_in"`
	DestIPIn        []string `yaml:"dest_ip_in"`
	DestIPNotIn     []string `yaml:"dest_ip_not_in"`
	DestPortIn      []uint16 `yaml:"dest_port_in"`
	DestPortNotIn   []uint16 `yaml:"dest_port_not_in"`
	UID             *uint32  `yaml:"uid"`
	Binary          string   `yaml:"binary"`
	Cgroup          string   `yaml:"cgroup"`
}

// Actions returns the parsed action tokens from match.action.
func (m Match) Actions() []string {
	if m.Action == "" {
		return nil
	}
	parts := strings.Split(m.Action, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (m Match) empty() bool {
	return m.Action == "" &&
		len(m.PathIn) == 0 && len(m.PathNotIn) == 0 &&
		len(m.DestIPIn) == 0 && len(m.DestIPNotIn) == 0 &&
		len(m.DestPortIn) == 0 && len(m.DestPortNotIn) == 0 &&
		m.UID == nil && m.Binary == "" && m.Cgroup == ""
}

// IsLiveState reports whether a rule participates in live enforcement compilation.
func IsLiveState(state string) bool {
	return state == StateEnforced
}

// IsShadowState reports whether a rule is shadow-only (P2 evaluation).
func IsShadowState(state string) bool {
	return state == StateShadow
}
