// Package deny parses kernel deny_verdict ringbuf records from the enforcer.
package deny

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Action codes mirror VERDICT_* in enforcer.bpf.c.
const (
	ActionOpen    = 1
	ActionUnlink  = 2
	ActionRename  = 3
	ActionConnect = 4
	ActionWrite   = 5
)

// verdictSize is sizeof(struct deny_verdict) in enforcer.bpf.c.
const (
	verdictSize      = 8 + 4 + 4 + 4 + 256
	offsetTimestamp  = 0
	offsetPID        = 8
	offsetRuleHash   = 12
	offsetAction     = 16
	offsetPath       = 20
)

// Verdict is the userspace view of a kernel deny_verdict ringbuf record.
type Verdict struct {
	TimestampNS uint64
	PID         uint32
	RuleIDHash  uint32
	Action      uint8
	Path        string
}

// Parse decodes raw ringbuf sample bytes from the deny_verdicts map.
func Parse(raw []byte) (Verdict, error) {
	if len(raw) < verdictSize {
		return Verdict{}, fmt.Errorf("deny verdict sample too short: %d", len(raw))
	}
	var v Verdict
	v.TimestampNS = binary.LittleEndian.Uint64(raw[offsetTimestamp : offsetTimestamp+8])
	v.PID = binary.LittleEndian.Uint32(raw[offsetPID : offsetPID+4])
	v.RuleIDHash = binary.LittleEndian.Uint32(raw[offsetRuleHash : offsetRuleHash+4])
	v.Action = raw[offsetAction]
	pathBytes := raw[offsetPath:verdictSize]
	if i := bytes.IndexByte(pathBytes, 0); i >= 0 {
		pathBytes = pathBytes[:i]
	}
	v.Path = string(pathBytes)
	return v, nil
}

// ActionName returns a stable action label for reporting.
func ActionName(action uint8) string {
	switch action {
	case ActionOpen:
		return "open"
	case ActionUnlink:
		return "unlink"
	case ActionRename:
		return "rename"
	case ActionConnect:
		return "connect"
	case ActionWrite:
		return "write"
	default:
		return fmt.Sprintf("action:%d", action)
	}
}
