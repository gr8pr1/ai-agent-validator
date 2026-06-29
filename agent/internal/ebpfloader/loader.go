// Package ebpfloader loads the embedded enrollment BPF object, attaches the
// process-lifecycle and action tracepoints, and exposes the ringbuf, tag map,
// and drop counters.
package ebpfloader

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	cringbuf "github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// tracepoint binds a BPF program in the object to a kernel tracepoint.
type tracepoint struct {
	group   string
	name    string
	program string
}

var tracepoints = []tracepoint{
	{"sched", "sched_process_exec", "handle_exec"},
	{"sched", "sched_process_fork", "handle_fork"},
	{"sched", "sched_process_exit", "handle_exit"},
	{"syscalls", "sys_enter_connect", "handle_connect"},
	{"syscalls", "sys_enter_openat", "handle_openat"},
	{"syscalls", "sys_enter_unlinkat", "handle_unlinkat"},
	{"syscalls", "sys_enter_renameat2", "handle_renameat2"},
}

// Loader owns the loaded collection, attached links, and ringbuf reader.
type Loader struct {
	coll  *ebpf.Collection
	links []link.Link
}

// Load parses and loads the BPF object into the kernel.
func Load(obj []byte) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}
	return &Loader{coll: coll}, nil
}

// Attach links every tracepoint program. Returns the list of attached names.
func (l *Loader) Attach() ([]string, error) {
	var attached []string
	for _, tp := range tracepoints {
		prog, ok := l.coll.Programs[tp.program]
		if !ok {
			return attached, fmt.Errorf("program %q not found in object", tp.program)
		}
		lnk, err := link.Tracepoint(tp.group, tp.name, prog, nil)
		if err != nil {
			return attached, fmt.Errorf("attach %s/%s: %w", tp.group, tp.name, err)
		}
		l.links = append(l.links, lnk)
		attached = append(attached, tp.group+"/"+tp.name)
	}
	return attached, nil
}

// Reader opens a ringbuf reader over the "events" map.
func (l *Loader) Reader() (*cringbuf.Reader, error) {
	m, ok := l.coll.Maps["events"]
	if !ok {
		return nil, fmt.Errorf("events map not found")
	}
	return cringbuf.NewReader(m)
}

// TagPID marks pid in the advisory kernel tag map.
func (l *Loader) TagPID(pid uint32) error {
	m, ok := l.coll.Maps["tagged_pids"]
	if !ok {
		return fmt.Errorf("tagged_pids map not found")
	}
	v := uint8(1)
	return m.Put(pid, v)
}

// UntagPID removes pid from the advisory kernel tag map.
func (l *Loader) UntagPID(pid uint32) error {
	m, ok := l.coll.Maps["tagged_pids"]
	if !ok {
		return fmt.Errorf("tagged_pids map not found")
	}
	return m.Delete(pid)
}

// Drops returns the total number of records the kernel dropped (ringbuf full).
func (l *Loader) Drops() (uint64, error) {
	m, ok := l.coll.Maps["drops"]
	if !ok {
		return 0, fmt.Errorf("drops map not found")
	}
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}

// Close detaches links and releases the collection.
func (l *Loader) Close() {
	for _, lnk := range l.links {
		_ = lnk.Close()
	}
	if l.coll != nil {
		l.coll.Close()
	}
}
