package fingerprint

import "testing"

func testSet() *Set {
	return &Set{Fingerprints: []Fingerprint{
		{
			ID: "claude-code", AgentID: "claude-code", IdentityClass: "interpreted",
			Match: Match{InterpreterBasename: "node", EnvMarkers: Markers{AnyOf: []string{"CLAUDECODE"}}},
		},
		{
			ID: "aider-pip-py3", AgentID: "aider", IdentityClass: "interpreted",
			Match: Match{InterpreterBasename: "python3", ArgvContains: []string{"*/bin/aider"}},
		},
		{
			ID: "compiled-bot", AgentID: "bot", IdentityClass: "compiled",
			Match: Match{InterpreterPath: "/opt/bot/agent"},
		},
	}}
}

func TestMatchInterpretedByEnvMarker(t *testing.T) {
	s := testSet()
	res := s.Evaluate(Observation{
		BinaryPath: "/usr/bin/node",
		Argv:       []string{"node", "/opt/claude/cli.js"},
		EnvKeys:    []string{"PATH", "CLAUDECODE"},
	})
	if !res.Matched || res.Fingerprint.AgentID != "claude-code" {
		t.Fatalf("expected claude-code match, got %+v trace=%v", res.Matched, res.Trace)
	}
}

func TestNoMatchBareNode(t *testing.T) {
	// A plain node process without the marker must NOT match (FP guard).
	s := testSet()
	res := s.Evaluate(Observation{
		BinaryPath: "/usr/bin/node",
		Argv:       []string{"node", "server.js"},
		EnvKeys:    []string{"PATH", "HOME"},
	})
	if res.Matched {
		t.Fatalf("bare node should not match, got %s", res.Fingerprint.AgentID)
	}
}

func TestMatchArgvGlob(t *testing.T) {
	s := testSet()
	res := s.Evaluate(Observation{
		BinaryPath: "/usr/bin/python3",
		Argv:       []string{"python3", "/usr/local/bin/aider", "--model"},
	})
	if !res.Matched || res.Fingerprint.AgentID != "aider" {
		t.Fatalf("expected aider match, got matched=%v trace=%v", res.Matched, res.Trace)
	}
}

func TestMatchCompiledByPathGlob(t *testing.T) {
	s := &Set{Fingerprints: []Fingerprint{{
		ID: "claude-code-versioned", AgentID: "claude-code",
		Match: Match{InterpreterPath: "*/.local/share/claude/versions/*"},
	}}}
	res := s.Evaluate(Observation{
		BinaryPath: "/root/.local/share/claude/versions/2.1.195",
		Argv:       []string{"rg", "--version"},
	})
	if !res.Matched || res.Fingerprint.ID != "claude-code-versioned" {
		t.Fatalf("expected versioned claude match, got matched=%v trace=%v", res.Matched, res.Trace)
	}
}

func TestMatchNativeClaudeBasename(t *testing.T) {
	s := &Set{Fingerprints: []Fingerprint{{
		ID: "claude-code-native", AgentID: "claude-code",
		Match: Match{InterpreterBasename: "claude"},
	}}}
	res := s.Evaluate(Observation{
		BinaryPath: "/root/.local/bin/claude",
		Argv:       []string{"claude"},
	})
	if !res.Matched || res.Fingerprint.ID != "claude-code-native" {
		t.Fatalf("expected native claude match, got matched=%v trace=%v", res.Matched, res.Trace)
	}
}

func TestMatchAiderModule(t *testing.T) {
	s := &Set{Fingerprints: []Fingerprint{{
		ID: "aider-module-py3", AgentID: "aider",
		Match: Match{InterpreterBasename: "python3", ArgvContains: []string{"-m", "aider"}},
	}}}
	res := s.Evaluate(Observation{
		BinaryPath: "/usr/bin/python3",
		Argv:       []string{"python3", "-m", "aider", "--model", "sonnet"},
	})
	if !res.Matched || res.Fingerprint.ID != "aider-module-py3" {
		t.Fatalf("expected aider module match, got matched=%v trace=%v", res.Matched, res.Trace)
	}
}

func TestMatchCursorCLI(t *testing.T) {
	s := &Set{Fingerprints: []Fingerprint{{
		ID: "cursor-cli-node", AgentID: "cursor",
		Match: Match{InterpreterBasename: "node", ArgvContains: []string{"*/.local/share/cursor-agent/*"}},
	}}}
	res := s.Evaluate(Observation{
		BinaryPath: "/usr/bin/node",
		Argv:       []string{"node", "/home/user/.local/share/cursor-agent/versions/2025.10.22/index.js"},
	})
	if !res.Matched || res.Fingerprint.ID != "cursor-cli-node" {
		t.Fatalf("expected cursor cli match, got matched=%v trace=%v", res.Matched, res.Trace)
	}
}

func TestMatchCursorIDEShell(t *testing.T) {
	s := &Set{Fingerprints: []Fingerprint{{
		ID: "cursor-ide-shell-bash", AgentID: "cursor",
		Match: Match{
			InterpreterBasename: "bash",
			EnvMarkers:          Markers{AnyOf: []string{"CURSOR_AGENT"}},
		},
	}}}
	res := s.Evaluate(Observation{
		BinaryPath: "/usr/bin/bash",
		Argv:       []string{"bash", "-c", "git status"},
		EnvKeys:    []string{"PATH", "CURSOR_AGENT"},
	})
	if !res.Matched || res.Fingerprint.ID != "cursor-ide-shell-bash" {
		t.Fatalf("expected cursor ide shell match, got matched=%v trace=%v", res.Matched, res.Trace)
	}
}

func TestMatchCompiledByPath(t *testing.T) {
	s := testSet()
	res := s.Evaluate(Observation{BinaryPath: "/opt/bot/agent", Argv: []string{"agent"}})
	if !res.Matched || res.Fingerprint.AgentID != "bot" {
		t.Fatalf("expected bot match, got matched=%v", res.Matched)
	}
}

func TestTracePopulatedOnMiss(t *testing.T) {
	s := testSet()
	res := s.Evaluate(Observation{BinaryPath: "/bin/ls", Argv: []string{"ls"}})
	if res.Matched {
		t.Fatal("ls should not match")
	}
	if len(res.Trace) != len(s.Fingerprints) {
		t.Fatalf("expected a trace entry per fingerprint, got %d", len(res.Trace))
	}
}
