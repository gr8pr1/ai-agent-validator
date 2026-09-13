package policy

import (
	"fmt"
	"os"
	"strings"

	yaml "go.yaml.in/yaml/v2"
)

// PromoteRuleOptions configures in-place rule state promotion (P5 ops).
type PromoteRuleOptions struct {
	BumpVersion bool
	NewState    string
}

// PromoteRule updates one rule's state in a bundle YAML file.
func PromoteRule(path, ruleID string, opts PromoteRuleOptions) error {
	if opts.NewState == "" {
		opts.NewState = StateEnforced
	}
	switch opts.NewState {
	case StateShadow, StateEnforced, StateDraft, StateRetired:
	default:
		return fmt.Errorf("invalid state %q", opts.NewState)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	b, err := Parse(data)
	if err != nil {
		return err
	}
	found := false
	for i := range b.Rules {
		if b.Rules[i].ID == ruleID {
			b.Rules[i].State = opts.NewState
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("rule %q not found in %s", ruleID, path)
	}
	if opts.BumpVersion {
		b.Version++
	}
	if _, err := Compile(b); err != nil {
		return fmt.Errorf("promoted bundle does not compile: %w", err)
	}
	out, err := yaml.Marshal(&Document{PolicyBundle: *b})
	if err != nil {
		return err
	}
	var sb strings.Builder
	sb.WriteString("# Updated by policyctl promote; re-sign before load.\n")
	sb.Write(out)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
