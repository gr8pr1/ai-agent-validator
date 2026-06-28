// Package fingerprint loads and evaluates the Mode B fingerprint set: the
// operator-maintained list of known-agent binary/argv/env signatures used to
// identify AI-agent processes at exec time.
package fingerprint

import (
	"fmt"
	"os"
	"path"
	"strings"

	yaml "go.yaml.in/yaml/v2"
)

// Markers is a set of environment variable names; any one present satisfies it.
type Markers struct {
	AnyOf []string `yaml:"any_of"`
}

// Match is the AND of all non-empty conditions.
type Match struct {
	InterpreterBasename string   `yaml:"interpreter_basename"`
	InterpreterPath     string   `yaml:"interpreter_path"`
	ArgvContains        []string `yaml:"argv_contains"`
	EnvMarkers          Markers  `yaml:"env_markers"`
}

// Fingerprint is one known-agent signature.
type Fingerprint struct {
	ID            string `yaml:"id"`
	AgentID       string `yaml:"agent_id"`
	Match         Match  `yaml:"match"`
	IdentityClass string `yaml:"identity_class"` // "interpreted" | "compiled"
	Confidence    string `yaml:"confidence"`     // "high" | "low"
}

// Set is the loaded fingerprint collection.
type Set struct {
	Fingerprints []Fingerprint `yaml:"fingerprints"`
}

// Load reads and validates a fingerprint YAML file.
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Set
	if err := yaml.UnmarshalStrict(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for i, fp := range s.Fingerprints {
		if fp.ID == "" || fp.AgentID == "" {
			return nil, fmt.Errorf("fingerprint #%d: id and agent_id are required", i)
		}
		if fp.Match.empty() {
			return nil, fmt.Errorf("fingerprint %q: match has no conditions", fp.ID)
		}
	}
	return &s, nil
}

func (m Match) empty() bool {
	return m.InterpreterBasename == "" && m.InterpreterPath == "" &&
		len(m.ArgvContains) == 0 && len(m.EnvMarkers.AnyOf) == 0
}

// Observation is the exec context evaluated against the set.
type Observation struct {
	BinaryPath string   // resolved exe path
	Argv       []string // bounded prefix
	EnvKeys    []string // env variable names present (bounded prefix)
}

// Result is the outcome of evaluating the set, including a per-condition trace
// for debugging Mode B (the key reason a process did/didn't enroll).
type Result struct {
	Matched     bool
	Fingerprint *Fingerprint
	Trace       []string
}

// Evaluate returns the first matching fingerprint plus a trace of every attempt.
func (s *Set) Evaluate(obj Observation) Result {
	var trace []string
	base := path.Base(obj.BinaryPath)
	envSet := make(map[string]struct{}, len(obj.EnvKeys))
	for _, k := range obj.EnvKeys {
		envSet[k] = struct{}{}
	}

	for i := range s.Fingerprints {
		fp := &s.Fingerprints[i]
		ok, why := matches(fp.Match, base, obj, envSet)
		trace = append(trace, fmt.Sprintf("%s: %s", fp.ID, why))
		if ok {
			return Result{Matched: true, Fingerprint: fp, Trace: trace}
		}
	}
	return Result{Matched: false, Trace: trace}
}

func matches(m Match, base string, obj Observation, envSet map[string]struct{}) (bool, string) {
	if m.InterpreterPath != "" && m.InterpreterPath != obj.BinaryPath {
		return false, fmt.Sprintf("interpreter_path %q != %q", m.InterpreterPath, obj.BinaryPath)
	}
	if m.InterpreterBasename != "" && m.InterpreterBasename != base {
		return false, fmt.Sprintf("interpreter_basename %q != %q", m.InterpreterBasename, base)
	}
	for _, glob := range m.ArgvContains {
		if !argvHasGlob(obj.Argv, glob) {
			return false, fmt.Sprintf("argv_contains %q not found", glob)
		}
	}
	if len(m.EnvMarkers.AnyOf) > 0 {
		found := ""
		for _, k := range m.EnvMarkers.AnyOf {
			if _, ok := envSet[k]; ok {
				found = k
				break
			}
		}
		if found == "" {
			return false, fmt.Sprintf("env_markers any_of %v none present", m.EnvMarkers.AnyOf)
		}
	}
	return true, "matched"
}

// argvHasGlob reports whether any argv element matches the wildcard pattern.
func argvHasGlob(argv []string, pattern string) bool {
	for _, a := range argv {
		if wildcardMatch(pattern, a) {
			return true
		}
	}
	return false
}

// wildcardMatch matches a pattern where '*' spans any characters (including
// path separators). This is more intuitive than filepath.Match for argv/path
// matching: "*/aider" matches "/usr/local/bin/aider".
func wildcardMatch(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	segs := strings.Split(pattern, "*")
	// Anchor the first and last segments; require middle segments in order.
	if first := segs[0]; first != "" {
		if !strings.HasPrefix(s, first) {
			return false
		}
		s = s[len(first):]
	}
	last := segs[len(segs)-1]
	mids := segs[1 : len(segs)-1]
	for _, m := range mids {
		if m == "" {
			continue
		}
		i := strings.Index(s, m)
		if i < 0 {
			return false
		}
		s = s[i+len(m):]
	}
	return strings.HasSuffix(s, last)
}
