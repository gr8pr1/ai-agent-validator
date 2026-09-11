package ebpfloader

import "testing"

func TestParseCgroupShow(t *testing.T) {
	sample := `ID       AttachType      AttachFlags     Name
123      connect4        multi           enforce_cgroup_connect4
124      connect6        multi           enforce_cgroup_connect6
125      connect4        multi           enforce_cgroup_connect4
`
	progs := ParseCgroupShow([]byte(sample))
	if len(progs) != 3 {
		t.Fatalf("got %d progs want 3", len(progs))
	}
	if progs[0].ID != 123 || progs[0].AttachType != "connect4" || progs[0].Name != "enforce_cgroup_connect4" {
		t.Fatalf("prog0=%+v", progs[0])
	}
	c4, c6 := countConnectHooks(progs)
	if c4 != 2 || c6 != 1 {
		t.Fatalf("connect4=%d connect6=%d", c4, c6)
	}
}

func TestParseCgroupShowHeaderOnly(t *testing.T) {
	progs := ParseCgroupShow([]byte("ID       AttachType      AttachFlags     Name\n"))
	if len(progs) != 0 {
		t.Fatalf("got %d want 0", len(progs))
	}
}
