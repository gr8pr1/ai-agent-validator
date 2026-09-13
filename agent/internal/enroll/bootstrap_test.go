package enroll

import (
	"os"
	"testing"
)

func TestReadProcCmdlineSelf(t *testing.T) {
	pid := uint32(os.Getpid())
	args := readProcCmdline(pid)
	if len(args) == 0 {
		t.Fatal("expected non-empty cmdline for self")
	}
}

func TestListProcessesIncludesSelf(t *testing.T) {
	ppids := listProcesses()
	if len(ppids) == 0 {
		t.Fatal("expected processes")
	}
	if _, ok := ppids[uint32(os.Getpid())]; !ok {
		t.Fatal("expected self in process list")
	}
}
