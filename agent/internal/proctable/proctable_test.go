package proctable

import (
	"testing"
	"time"
)

func TestTagAndInheritByFork(t *testing.T) {
	tbl := New()
	now := time.Now()

	// Anchor process execs and is enrolled.
	tbl.OnExec(100, 1, 1, "node", "/usr/bin/node", now)
	tbl.Tag(100, "claude-code", ModeB, "fingerprint:claude-code")

	// It forks a child shell.
	child := tbl.OnFork(101, 100, "bash", now)
	if !child.Tagged() || child.AgentID != "claude-code" {
		t.Fatalf("forked child should inherit tag, got %+v", child)
	}
	if child.Mode != ModeInherited || child.RootPID != 100 {
		t.Fatalf("inherited child metadata wrong: %+v", child)
	}
}

func TestInheritByExecFromTaggedParent(t *testing.T) {
	tbl := New()
	now := time.Now()
	tbl.OnExec(200, 1, 1, "node", "/usr/bin/node", now)
	tbl.Tag(200, "cursor", ModeB, "fingerprint:cursor")

	// Child appears via exec with the tagged parent as ppid (no prior fork seen).
	p, tagged := tbl.OnExec(201, 5, 200, "curl", "/usr/bin/curl", now)
	if !tagged || p.AgentID != "cursor" || p.RootPID != 200 {
		t.Fatalf("exec child should inherit from tagged parent: %+v", p)
	}
}

func TestUntaggedForkNotStored(t *testing.T) {
	tbl := New()
	now := time.Now()
	// Parent is untagged; its fork must not be persisted (memory-bound).
	tbl.OnExec(600, 1, 1, "bash", "/bin/bash", now)
	tbl.OnFork(601, 600, "ls", now)
	if _, ok := tbl.Get(601); ok {
		t.Fatal("untagged fork should not be stored")
	}
}

func TestReuseSafeIdentityResetsTag(t *testing.T) {
	tbl := New()
	now := time.Now()
	// pid 700 is a tagged agent with start time 1000; its exit was missed.
	tbl.OnExec(700, 1000, 1, "node", "/usr/bin/node", now)
	tbl.Tag(700, "claude-code", ModeB, "fingerprint:claude-code")

	// pid 700 is reused by an unrelated process (different start time).
	p, tagged := tbl.OnExec(700, 2000, 9, "ls", "/bin/ls", now)
	if tagged || p.Tagged() {
		t.Fatalf("reused pid must not keep the prior agent tag: %+v", p)
	}
	if p.Binary != "/bin/ls" || p.StartNS != 2000 {
		t.Fatalf("reused entry not refreshed: %+v", p)
	}
}

func TestUntaggedStaysUntagged(t *testing.T) {
	tbl := New()
	now := time.Now()
	p, tagged := tbl.OnExec(300, 1, 1, "ls", "/bin/ls", now)
	if tagged || p.Tagged() {
		t.Fatalf("unrelated process must not be tagged: %+v", p)
	}
}

func TestPruneExited(t *testing.T) {
	tbl := New()
	old := time.Now().Add(-10 * time.Minute)
	tbl.OnExec(400, 1, 1, "node", "/usr/bin/node", old)
	tbl.Tag(400, "a", ModeB, "x")
	tbl.OnExit(400, old)

	if n := tbl.Prune(time.Minute); n != 1 {
		t.Fatalf("expected 1 pruned, got %d", n)
	}
	if _, ok := tbl.Get(400); ok {
		t.Fatal("pruned proc should be gone")
	}
}

func TestTaggedSnapshotExcludesExited(t *testing.T) {
	tbl := New()
	now := time.Now()
	tbl.OnExec(500, 1, 1, "node", "/usr/bin/node", now)
	tbl.Tag(500, "a", ModeB, "x")
	tbl.OnExec(501, 1, 1, "node", "/usr/bin/node", now)
	tbl.Tag(501, "a", ModeB, "x")
	tbl.OnExit(501, now)

	snap := tbl.TaggedSnapshot()
	if len(snap) != 1 || snap[0].PID != 500 {
		t.Fatalf("snapshot should only include live tagged procs, got %+v", snap)
	}
}
