package feedback

import (
	"fmt"
	"time"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/proctable"
)

const (
	DecisionDenied = "denied"
	RetryDoNot     = "do-not-retry"
	NatureHard     = "hard-policy (not a transient error)"
	AppealDefault  = "If this is genuinely required, a human must change the policy; you cannot bypass it."
)

// Decision is the structured policy-denial record surfaced to agent runtimes (architecture §5.6).
type Decision struct {
	Time          time.Time `json:"time"`
	Decision      string    `json:"decision"`
	Action        string    `json:"action"`
	Target        string    `json:"target,omitempty"`
	MatchedRule   string    `json:"matched_rule"`
	Reason        string    `json:"reason"`
	Retry         string    `json:"retry"`
	Nature        string    `json:"nature"`
	Appeal        string    `json:"appeal"`
	AgentID       string    `json:"agent_id,omitempty"`
	PID           uint32    `json:"pid"`
	PolicyVersion int       `json:"policy_version,omitempty"`
}

// NewDecision maps a kernel deny into a model-facing feedback record.
// at is wall-clock record time (not bpf ktime); zero uses time.Now().
func NewDecision(at time.Time, pid uint32, action, target, agentID, ruleID, reason string, policyVersion int) Decision {
	if at.IsZero() {
		at = time.Now()
	}
	if reason == "" {
		reason = fmt.Sprintf("Action %q was blocked by host policy rule %q.", action, ruleID)
	}
	return Decision{
		Time:          at,
		Decision:      DecisionDenied,
		Action:        action,
		Target:        target,
		MatchedRule:   ruleID,
		Reason:        reason,
		Retry:         RetryDoNot,
		Nature:        NatureHard,
		Appeal:        AppealDefault,
		AgentID:       agentID,
		PID:           pid,
		PolicyVersion: policyVersion,
	}
}

// AgentContext enriches a decision from the process table when available.
func AgentContext(tbl *proctable.Table, pid uint32) (agentID, comm string) {
	if tbl == nil {
		return "", ""
	}
	if p, ok := tbl.Get(pid); ok {
		return p.AgentID, p.Comm
	}
	return "", ""
}
