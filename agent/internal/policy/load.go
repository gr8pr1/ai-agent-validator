package policy

import (
	"fmt"
	"net"
	"os"
	"strings"

	yaml "go.yaml.in/yaml/v2"
)

// Load reads and validates a policy bundle from path.
func Load(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse validates policy bundle bytes.
func Parse(data []byte) (*Bundle, error) {
	var doc Document
	if err := yaml.UnmarshalStrict(data, &doc); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	b := &doc.PolicyBundle
	if err := b.validate(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *Bundle) validate() error {
	if b.Version <= 0 {
		return fmt.Errorf("policy_bundle.version must be > 0")
	}
	if strings.TrimSpace(b.AgentScope) == "" {
		return fmt.Errorf("policy_bundle.agent_scope is required")
	}
	if b.DefaultAction == "" {
		b.DefaultAction = DefaultActionAllow
	}
	switch b.DefaultAction {
	case DefaultActionAllow, DefaultActionDeny:
	default:
		return fmt.Errorf("policy_bundle.default_action must be allow|deny, got %q", b.DefaultAction)
	}
	if b.FailDirection == "" {
		b.FailDirection = FailDirectionOpen
	}
	switch b.FailDirection {
	case FailDirectionOpen, FailDirectionClosed:
	default:
		return fmt.Errorf("policy_bundle.fail_direction must be open|closed, got %q", b.FailDirection)
	}

	seen := make(map[string]struct{}, len(b.Rules))
	for i, r := range b.Rules {
		if err := r.validate(i); err != nil {
			return err
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("rule id %q is duplicated", r.ID)
		}
		seen[r.ID] = struct{}{}
	}
	return nil
}

func (r *Rule) validate(idx int) error {
	prefix := fmt.Sprintf("rule #%d", idx)
	if r.ID == "" {
		return fmt.Errorf("%s: id is required", prefix)
	}
	if strings.TrimSpace(r.Rationale) == "" {
		return fmt.Errorf("rule %q: rationale is required", r.ID)
	}
	if r.Decision == "" {
		return fmt.Errorf("rule %q: decision is required", r.ID)
	}
	switch r.Decision {
	case DecisionAllow, DecisionDeny, DecisionKill:
	default:
		return fmt.Errorf("rule %q: decision must be allow|deny|kill, got %q", r.ID, r.Decision)
	}
	if r.State == "" {
		r.State = StateDraft
	}
	switch r.State {
	case StateDraft, StateShadow, StateEnforced, StateRetired, StateRollback:
	default:
		return fmt.Errorf("rule %q: state must be draft|shadow|enforced|retired|rollback, got %q", r.ID, r.State)
	}
	if r.Match.empty() {
		return fmt.Errorf("rule %q: match must specify at least one condition", r.ID)
	}
	if len(r.Match.Actions()) == 0 {
		return fmt.Errorf("rule %q: match.action is required", r.ID)
	}
	for _, act := range r.Match.Actions() {
		if _, ok := validActions[act]; !ok {
			return fmt.Errorf("rule %q: unknown action %q", r.ID, act)
		}
	}
	for _, cidr := range append(append([]string{}, r.Match.DestIPIn...), r.Match.DestIPNotIn...) {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			if ip := net.ParseIP(cidr); ip == nil {
				return fmt.Errorf("rule %q: invalid CIDR/IP %q", r.ID, cidr)
			}
		}
	}
	return nil
}
