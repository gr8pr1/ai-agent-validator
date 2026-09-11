package ebpfloader

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	cringbuf "github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/policy"
)

// lsmProgram binds a BPF LSM program in the enforcer object.
type lsmProgram struct {
	name string
}

var lsmPrograms = []lsmProgram{
	{name: "enforce_file_open"},
	{name: "enforce_path_unlink"},
	{name: "enforce_path_rename"},
	{name: "enforce_socket_connect"},
}

// enforceStatCount must match STAT_ENFORCE_MAX in enforcer.bpf.c.
const enforceStatCount = 6

const (
	enforceStatFileOpen = iota
	enforceStatGatePass
	enforceStatOpenatFmod
	enforceStatOpenatDeny
	enforceStatConnectFmod
	enforceStatConnectDeny
)

// syscallPrograms are optional fmod_ret hooks (x86_64 only in the BPF object).
var syscallPrograms = []string{
	"enforce_openat_entry",
	"enforce_connect_entry",
}

type cgroupProgram struct {
	name   string
	attach ebpf.AttachType
}

var cgroupPrograms = []cgroupProgram{
	{name: "enforce_cgroup_connect4", attach: ebpf.AttachCGroupInet4Connect},
	{name: "enforce_cgroup_connect6", attach: ebpf.AttachCGroupInet6Connect},
}

// EnforceStats aggregates per-CPU enforce_stats counters from the enforcer.
type EnforceStats struct {
	FileOpenCalls  uint64
	GatePass       uint64
	OpenatFmod     uint64
	OpenatDeny     uint64
	ConnectFmod    uint64
	ConnectDeny    uint64
}

// PolicyCtrl is the userspace view of the policy_ctrl BPF map value.
type PolicyCtrl struct {
	EnforcementActive uint8
	FailClosed        uint8
	DefaultDeny       uint8
	PolicyVersion     uint32
}

// EnforcerLoader owns the P3 enforcement BPF collection and LSM links.
type EnforcerLoader struct {
	coll  *ebpf.Collection
	links []link.Link
}

// LoadEnforcer parses and loads the enforcer BPF object into the kernel.
// When replacements includes "tagged_pids", the enforcer shares the enroll
// advisory tag map so LSM hooks observe the same tagged set as tracepoints.
func LoadEnforcer(obj []byte, replacements map[string]*ebpf.Map) (*EnforcerLoader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return nil, fmt.Errorf("load enforcer spec: %w", err)
	}
	opts := ebpf.CollectionOptions{
		MapReplacements: replacements,
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, fmt.Errorf("new enforcer collection: %w", err)
	}
	return &EnforcerLoader{coll: coll}, nil
}

// AttachSyscallEnforcement links fmod_ret syscall programs when present in the object.
func (l *EnforcerLoader) AttachSyscallEnforcement() ([]string, error) {
	var attached []string
	for _, name := range syscallPrograms {
		prog, ok := l.coll.Programs[name]
		if !ok {
			continue
		}
		lnk, err := link.AttachTracing(link.TracingOptions{
			Program:    prog,
			AttachType: ebpf.AttachModifyReturn,
		})
		if err != nil {
			return attached, fmt.Errorf("attach fmod_ret %s: %w", name, err)
		}
		l.links = append(l.links, lnk)
		attached = append(attached, "fmod_ret/"+name)
	}
	return attached, nil
}

// AttachCgroupEgress links cgroup/connect4 and connect6 programs to cgroupPath.
func (l *EnforcerLoader) AttachCgroupEgress(cgroupPath string) ([]string, error) {
	var attached []string
	for _, cp := range cgroupPrograms {
		prog, ok := l.coll.Programs[cp.name]
		if !ok {
			return attached, fmt.Errorf("cgroup program %q not found in enforcer object", cp.name)
		}
		lnk, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  cp.attach,
			Program: prog,
		})
		if err != nil {
			return attached, fmt.Errorf("attach cgroup %s to %s: %w", cp.name, cgroupPath, err)
		}
		l.links = append(l.links, lnk)
		attached = append(attached, "cgroup/"+cp.name)
	}
	if len(attached) == 0 {
		return attached, fmt.Errorf("no cgroup programs attached to %s", cgroupPath)
	}
	return attached, nil
}

// AttachLSM links every LSM program. Requires CONFIG_BPF_LSM and lsm=...,bpf.
func (l *EnforcerLoader) AttachLSM() ([]string, error) {
	var attached []string
	for _, lp := range lsmPrograms {
		prog, ok := l.coll.Programs[lp.name]
		if !ok {
			return attached, fmt.Errorf("program %q not found in enforcer object", lp.name)
		}
		lnk, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			return attached, fmt.Errorf("attach LSM %s: %w", lp.name, err)
		}
		l.links = append(l.links, lnk)
		attached = append(attached, "lsm/"+lp.name)
	}
	return attached, nil
}

// SetPolicyCtrl writes the policy_ctrl map (key 0).
func (l *EnforcerLoader) SetPolicyCtrl(c PolicyCtrl) error {
	m, ok := l.coll.Maps["policy_ctrl"]
	if !ok {
		return fmt.Errorf("policy_ctrl map not found")
	}
	val := struct {
		EnforcementActive uint8
		FailClosed        uint8
		DefaultDeny       uint8
		_                 uint8
		PolicyVersion     uint32
	}{
		EnforcementActive: c.EnforcementActive,
		FailClosed:        c.FailClosed,
		DefaultDeny:       c.DefaultDeny,
		PolicyVersion:     c.PolicyVersion,
	}
	var k uint32
	return m.Put(k, val)
}

// TagPID marks pid in the enforcer tagged_pids map (mirrors enroll loader).
func (l *EnforcerLoader) TagPID(pid uint32) error {
	m, ok := l.coll.Maps["tagged_pids"]
	if !ok {
		return fmt.Errorf("tagged_pids map not found")
	}
	v := uint8(1)
	return m.Put(pid, v)
}

// UntagPID removes pid from the enforcer tagged_pids map.
func (l *EnforcerLoader) UntagPID(pid uint32) error {
	m, ok := l.coll.Maps["tagged_pids"]
	if !ok {
		return fmt.Errorf("tagged_pids map not found")
	}
	return m.Delete(pid)
}

// DenyReader opens a ringbuf reader over the deny_verdicts map.
func (l *EnforcerLoader) DenyReader() (*cringbuf.Reader, error) {
	m, ok := l.coll.Maps["deny_verdicts"]
	if !ok {
		return nil, fmt.Errorf("deny_verdicts map not found")
	}
	return cringbuf.NewReader(m)
}

// Program returns a loaded BPF program by name.
func (l *EnforcerLoader) Program(name string) *ebpf.Program {
	if l.coll == nil {
		return nil
	}
	return l.coll.Programs[name]
}

// Maps exposes the underlying collection maps (for mapload in P3.2).
func (l *EnforcerLoader) Maps() map[string]*ebpf.Map {
	if l.coll == nil {
		return nil
	}
	return l.coll.Maps
}

// EnforcerMaps returns the policy map subset for LoadLive.
func (l *EnforcerLoader) EnforcerMaps() policy.EnforcerMapSet {
	m := l.Maps()
	return policy.EnforcerMapSet{
		PolicyCtrl: m["policy_ctrl"],
		PathDeny:   m["path_deny"],
		PathAllow:  m["path_allow"],
		InodeDeny:  m["inode_deny"],
		InodeAllow: m["inode_allow"],
		IPDeny:     m["ip_deny"],
		IPAllow:    m["ip_allow"],
		PortDeny:   m["port_deny"],
		PortAllow:  m["port_allow"],
	}
}

// LoadLivePolicy loads enforced rules into kernel maps (P3.2).
func (l *EnforcerLoader) LoadLivePolicy(cp *policy.CompiledPolicy, ctrl policy.PolicyCtrlValues) (policy.LoadStats, error) {
	return policy.LoadLive(cp, l.EnforcerMaps(), ctrl)
}

// EnforceStats reads and sums per-CPU enforce_stats counters.
func (l *EnforcerLoader) EnforceStats() (EnforceStats, error) {
	m, ok := l.coll.Maps["enforce_stats"]
	if !ok {
		return EnforceStats{}, fmt.Errorf("enforce_stats map not found")
	}
	sum := func(key uint32) (uint64, error) {
		var perCPU []uint64
		if err := m.Lookup(key, &perCPU); err != nil {
			return 0, err
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		return total, nil
	}
	fileOpen, err := sum(enforceStatFileOpen)
	if err != nil {
		return EnforceStats{}, err
	}
	gatePass, err := sum(enforceStatGatePass)
	if err != nil {
		return EnforceStats{}, err
	}
	openatFmod, err := sum(enforceStatOpenatFmod)
	if err != nil {
		return EnforceStats{}, err
	}
	openatDeny, err := sum(enforceStatOpenatDeny)
	if err != nil {
		return EnforceStats{}, err
	}
	connectFmod, err := sum(enforceStatConnectFmod)
	if err != nil {
		return EnforceStats{}, err
	}
	connectDeny, err := sum(enforceStatConnectDeny)
	if err != nil {
		return EnforceStats{}, err
	}
	return EnforceStats{
		FileOpenCalls: fileOpen,
		GatePass:      gatePass,
		OpenatFmod:    openatFmod,
		OpenatDeny:    openatDeny,
		ConnectFmod:   connectFmod,
		ConnectDeny:   connectDeny,
	}, nil
}

// Close detaches LSM links and releases the collection.
func (l *EnforcerLoader) Close() {
	for _, lnk := range l.links {
		_ = lnk.Close()
	}
	if l.coll != nil {
		l.coll.Close()
	}
}
