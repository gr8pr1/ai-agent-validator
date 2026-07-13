package policy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// ShadowReportRow is one aggregated shadow_deny count.
type ShadowReportRow struct {
	RuleID    string
	Source    string
	AgentID   string
	Count     int
}

// ShadowReport scans audit JSONL for shadow_deny events since the given time.
func ShadowReport(auditPath string, since time.Time) ([]ShadowReportRow, error) {
	f, err := os.Open(auditPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ShadowReportFromReader(f, since)
}

// ShadowReportFromReader scans r for shadow_deny events since the given time.
func ShadowReportFromReader(r io.Reader, since time.Time) ([]ShadowReportRow, error) {
	type key struct {
		rule, source, agent string
	}
	counts := make(map[key]int)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec struct {
			Event        string    `json:"event"`
			Time         time.Time `json:"time"`
			RuleID       string    `json:"rule_id"`
			ShadowSource string    `json:"shadow_source"`
			AgentID      string    `json:"agent_id"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Event != "shadow_deny" {
			continue
		}
		if !since.IsZero() && !rec.Time.IsZero() && rec.Time.Before(since) {
			continue
		}
		k := key{rule: rec.RuleID, source: rec.ShadowSource, agent: rec.AgentID}
		counts[k]++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	rows := make([]ShadowReportRow, 0, len(counts))
	for k, n := range counts {
		rows = append(rows, ShadowReportRow{
			RuleID: k.rule, Source: k.source, AgentID: k.agent, Count: n,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].RuleID != rows[j].RuleID {
			return rows[i].RuleID < rows[j].RuleID
		}
		if rows[i].Source != rows[j].Source {
			return rows[i].Source < rows[j].Source
		}
		return rows[i].AgentID < rows[j].AgentID
	})
	return rows, nil
}

// FormatShadowReport renders rows as a human-readable table.
func FormatShadowReport(rows []ShadowReportRow) string {
	if len(rows) == 0 {
		return "no shadow_deny events found\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-24s %-14s %-16s %6s\n", "rule_id", "source", "agent_id", "count")
	for _, r := range rows {
		fmt.Fprintf(&b, "%-24s %-14s %-16s %6d\n", r.RuleID, r.Source, r.AgentID, r.Count)
	}
	return b.String()
}
