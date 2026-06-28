// Package report emits enrollment decisions and tagged process-lifecycle
// records to the configured sinks (stdout in text/JSON, an append-only audit
// log). A future OTLP sink seam is sketched in otlp.go but inert in P0.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Record is one reportable observation.
type Record struct {
	Time     time.Time `json:"time"`
	Event    string    `json:"event"` // exec|fork|exit
	Enrolled bool      `json:"enrolled,omitempty"`
	PID      uint32    `json:"pid"`
	PPID     uint32    `json:"ppid,omitempty"`
	RootPID  uint32    `json:"root_pid,omitempty"`
	AgentID  string    `json:"agent_id,omitempty"`
	Mode     string    `json:"mode,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Comm     string    `json:"comm,omitempty"`
	Binary   string    `json:"binary,omitempty"`
	Argv     []string  `json:"argv,omitempty"`
}

// Reporter fans a Record out to stdout and an optional audit-log file.
type Reporter struct {
	format string
	out    io.Writer
	mu     sync.Mutex
	audit  *os.File
}

// New builds a Reporter. format is "text" or "json"; auditPath "" disables the
// file sink.
func New(format, auditPath string) (*Reporter, error) {
	r := &Reporter{format: format, out: os.Stdout}
	if auditPath != "" {
		f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open audit log: %w", err)
		}
		r.audit = f
	}
	return r, nil
}

// Emit writes the record to stdout (text or JSON) and the audit log (JSONL).
func (r *Reporter) Emit(rec Record) {
	if rec.Time.IsZero() {
		rec.Time = time.Now()
	}
	line := r.render(rec)
	jsonLine := jsonBytes(rec)

	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintln(r.out, line)
	if r.audit != nil {
		r.audit.Write(jsonLine)
		r.audit.Write([]byte{'\n'})
	}
}

// EmitAuditOnly writes one JSONL record to the audit log without stdout.
func (r *Reporter) EmitAuditOnly(rec Record) {
	if r.audit == nil {
		return
	}
	if rec.Time.IsZero() {
		rec.Time = time.Now()
	}
	jsonLine := jsonBytes(rec)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.audit.Write(jsonLine)
	r.audit.Write([]byte{'\n'})
}

func (r *Reporter) render(rec Record) string {
	if r.format == "json" {
		return string(jsonBytes(rec))
	}
	var b strings.Builder
	if rec.Enrolled {
		b.WriteString("ENROLL ")
	} else {
		b.WriteString(strings.ToUpper(rec.Event))
		b.WriteByte(' ')
	}
	fmt.Fprintf(&b, "pid=%d", rec.PID)
	if rec.PPID != 0 {
		fmt.Fprintf(&b, " ppid=%d", rec.PPID)
	}
	if rec.AgentID != "" {
		fmt.Fprintf(&b, " agent=%s mode=%s root=%d", rec.AgentID, rec.Mode, rec.RootPID)
	}
	if rec.Comm != "" {
		fmt.Fprintf(&b, " comm=%s", rec.Comm)
	}
	if rec.Binary != "" {
		fmt.Fprintf(&b, " bin=%s", rec.Binary)
	}
	if rec.Reason != "" {
		fmt.Fprintf(&b, " reason=%q", rec.Reason)
	}
	return b.String()
}

func jsonBytes(rec Record) []byte {
	b, err := json.Marshal(rec)
	if err != nil {
		return []byte(fmt.Sprintf(`{"error":%q}`, err.Error()))
	}
	return b
}

// Close flushes and closes the audit log.
func (r *Reporter) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.audit != nil {
		_ = r.audit.Close()
	}
}
