package feedback

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	ShimPrefix  = "AIBLOCKER_POLICY_FEEDBACK:"
	matchGrace  = 200 * time.Millisecond
	defaultWait = 500 * time.Millisecond
	defaultPoll = 50 * time.Millisecond
)

// LookupConfig selects where the shim reads recent policy feedback.
type LookupConfig struct {
	File    string
	URL     string
	AgentID string
	Wait    time.Duration
	Poll    time.Duration
}

// FindForPID returns the newest decision matching pid after since.
// Polls until Wait elapses when feedback may arrive after the child exits.
func FindForPID(cfg LookupConfig, pid uint32, since time.Time) (*Decision, error) {
	wait, poll := cfg.Wait, cfg.Poll
	if wait <= 0 {
		wait = defaultWait
	}
	if poll <= 0 {
		poll = defaultPoll
	}
	deadline := time.Now().Add(wait)
	var lastErr error
	for {
		list, err := collect(cfg, time.Until(deadline))
		if err != nil {
			lastErr = err
		}
		if d := matchPID(list, pid, since); d != nil {
			return d, nil
		}
		if time.Now().After(deadline) {
			return nil, lastErr
		}
		time.Sleep(poll)
	}
}

func collect(cfg LookupConfig, httpTimeout time.Duration) ([]Decision, error) {
	var out []Decision
	var errs []error
	if cfg.File != "" {
		list, err := RecentFromFile(cfg.File, 64)
		if err != nil {
			errs = append(errs, fmt.Errorf("feedback file: %w", err))
		} else {
			out = append(out, list...)
		}
	}
	if cfg.URL != "" {
		if httpTimeout <= 0 {
			httpTimeout = defaultPoll
		}
		list, err := FromHTTP(cfg.URL, cfg.AgentID, httpTimeout)
		if err != nil {
			errs = append(errs, fmt.Errorf("feedback HTTP: %w", err))
		} else {
			out = append(out, list...)
		}
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

func matchPID(list []Decision, pid uint32, since time.Time) *Decision {
	cutoff := since.Add(-matchGrace)
	var best *Decision
	for i := range list {
		d := &list[i]
		if d.PID != pid || d.Time.Before(cutoff) {
			continue
		}
		if best == nil || d.Time.After(best.Time) {
			best = d
		}
	}
	return best
}

// RecentFromFile reads up to limit trailing JSONL records from path.
func RecentFromFile(path string, limit int) ([]Decision, error) {
	if limit <= 0 {
		limit = 32
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const tailMax = 256 << 10
	start := int64(0)
	if st.Size() > tailMax {
		start = st.Size() - tailMax
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	var out []Decision
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var d Decision
		if err := json.Unmarshal(line, &d); err != nil {
			continue
		}
		out = append(out, d)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

// FromHTTP fetches recent feedback from the agent debug endpoint.
func FromHTTP(baseURL, agentID string, timeout time.Duration) ([]Decision, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if agentID != "" {
		q.Set("agent_id", agentID)
	} else if q.Get("limit") == "" {
		q.Set("limit", "32")
	}
	u.RawQuery = q.Encode()
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(u.String()) //nolint:gosec // URL comes from operator config
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feedback HTTP %d", resp.StatusCode)
	}
	var out []Decision
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// HumanMessage renders a concise explanation for agent runtimes.
func (d Decision) HumanMessage() string {
	msg := fmt.Sprintf("Policy blocked action %q", d.Action)
	if d.Target != "" {
		msg += fmt.Sprintf(" on %q", d.Target)
	}
	msg += fmt.Sprintf(" (rule %q). %s Retry: %s.", d.MatchedRule, d.Reason, d.Retry)
	return msg
}

// ShimLine returns the machine-readable line written by the shim on stderr.
func (d Decision) ShimLine() string {
	b, _ := json.Marshal(d)
	return ShimPrefix + string(b)
}
