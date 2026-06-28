package event

import (
	"encoding/binary"
	"testing"
)

// buildExec creates a full-size exec record with the given tail content.
func buildExec(pid, ppid uint32, comm, filename string, argv, env []string) []byte {
	b := make([]byte, RecordSize)
	binary.LittleEndian.PutUint64(b[0:8], 111)   // timestamp
	binary.LittleEndian.PutUint64(b[8:16], 222)  // start_time
	binary.LittleEndian.PutUint64(b[16:24], 333) // cgroup
	binary.LittleEndian.PutUint32(b[24:28], pid)
	binary.LittleEndian.PutUint32(b[28:32], ppid)
	binary.LittleEndian.PutUint32(b[32:36], 1000) // uid
	b[36] = TypeExec
	copy(b[44:60], comm)

	fn := []byte(filename)
	copy(b[filenameOff:], fn)
	binary.LittleEndian.PutUint16(b[42:44], uint16(len(fn)))

	argvBlob := joinNul(argv)
	copy(b[argvOff:], argvBlob)
	binary.LittleEndian.PutUint16(b[38:40], uint16(len(argvBlob)))

	envBlob := joinNul(env)
	copy(b[envOff:], envBlob)
	binary.LittleEndian.PutUint16(b[40:42], uint16(len(envBlob)))
	return b
}

func joinNul(items []string) []byte {
	var out []byte
	for _, s := range items {
		out = append(out, []byte(s)...)
		out = append(out, 0)
	}
	return out
}

func TestParseExec(t *testing.T) {
	rec := buildExec(42, 7, "node", "/usr/bin/node",
		[]string{"node", "/opt/claude/cli.js", "--flag"},
		[]string{"PATH=/usr/bin", "CLAUDECODE=1"})

	e, err := Parse(rec)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if e.Type != TypeExec || e.PID != 42 || e.PPID != 7 {
		t.Fatalf("header mismatch: %+v", e)
	}
	if e.Comm != "node" || e.Filename != "/usr/bin/node" {
		t.Fatalf("comm/filename mismatch: comm=%q filename=%q", e.Comm, e.Filename)
	}
	if len(e.Argv) != 3 || e.Argv[1] != "/opt/claude/cli.js" {
		t.Fatalf("argv mismatch: %v", e.Argv)
	}
	if len(e.Env) != 2 || e.Env[1] != "CLAUDECODE=1" {
		t.Fatalf("env mismatch: %v", e.Env)
	}
}

func TestParseHeaderOnly(t *testing.T) {
	b := make([]byte, HeaderSize)
	binary.LittleEndian.PutUint32(b[24:28], 99)
	binary.LittleEndian.PutUint32(b[28:32], 1)
	b[36] = TypeFork
	copy(b[44:60], "bash")

	e, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if e.Type != TypeFork || e.PID != 99 || e.PPID != 1 || e.Comm != "bash" {
		t.Fatalf("fork parse mismatch: %+v", e)
	}
	if e.Argv != nil || e.Env != nil || e.Filename != "" {
		t.Fatalf("header-only record should have no tail: %+v", e)
	}
}

func TestParseTooShort(t *testing.T) {
	if _, err := Parse(make([]byte, 10)); err != ErrShort {
		t.Fatalf("expected ErrShort, got %v", err)
	}
}

func TestSplitNul(t *testing.T) {
	got := splitNul([]byte("a\x00bb\x00\x00ccc"))
	want := []string{"a", "bb", "ccc"}
	if len(got) != len(want) {
		t.Fatalf("splitNul len: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitNul[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}
