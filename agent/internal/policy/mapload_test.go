package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func testEnforcerMaps(t *testing.T) EnforcerMapSet {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock rlimit (%v); run with ulimit -l unlimited or sudo", err)
	}
	objPath := filepath.Join("..", "..", "cmd", "agent", "bpf", "enforcer.bpf.o")
	data, err := os.ReadFile(objPath)
	if err != nil {
		t.Skip("enforcer.bpf.o missing; run `make bpf` first")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { coll.Close() })
	return EnforcerMapSet{
		PolicyCtrl: coll.Maps["policy_ctrl"],
		PathDeny:   coll.Maps["path_deny"],
		PathAllow:  coll.Maps["path_allow"],
		InodeDeny:  coll.Maps["inode_deny"],
		InodeAllow: coll.Maps["inode_allow"],
		IPDeny:     coll.Maps["ip_deny"],
		IPAllow:    coll.Maps["ip_allow"],
		PortDeny:   coll.Maps["port_deny"],
		PortAllow:  coll.Maps["port_allow"],
	}
}

func TestPathPatternToLPM(t *testing.T) {
	k, err := pathPatternToLPM("/etc/shadow")
	if err != nil {
		t.Fatal(err)
	}
	if k.Prefixlen != uint32(len("/etc/shadow"))*8 {
		t.Fatalf("prefixlen=%d", k.Prefixlen)
	}
	k, err = pathPatternToLPM("/etc/*")
	if err != nil {
		t.Fatal(err)
	}
	want := "/etc/"
	if string(k.Data[:len(want)]) != want {
		t.Fatalf("got prefix %q", string(k.Data[:len(want)]))
	}
	_, err = pathPatternToLPM("/home/*/.ssh/*")
	if err == nil {
		t.Fatal("expected error for mid-glob")
	}
}

func TestCIDRToLPM(t *testing.T) {
	k, err := cidrToLPM("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if k.Prefixlen != 8 {
		t.Fatalf("prefixlen=%d want 8", k.Prefixlen)
	}
}

func TestLoadLivePathDeny(t *testing.T) {
	maps := testEnforcerMaps(t)
	path := t.TempDir() + "/secret"
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cp := &CompiledPolicy{
		Version:       1,
		DefaultAction: DefaultActionAllow,
		FailDirection: FailDirectionOpen,
		Live: []CompiledRule{{
			ID: "deny-secret", Rationale: "no secret file", Decision: DecisionDeny,
			Action: "open", PathIn: []string{path}, Specificity: 12,
		}},
	}
	stats, err := LoadLive(cp, maps, PolicyCtrlValues{EnforcementActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if stats.PathDeny != 1 || stats.InodeDeny != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	var v pathRule
	if err := maps.PathDeny.Lookup(mustLPM(path), &v); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if v.Decision != MapDecisionDeny || v.Action != VerdictOpen {
		t.Fatalf("val=%+v", v)
	}
	ikey, err := pathToInodeKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := maps.InodeDeny.Lookup(ikey, &v); err != nil {
		t.Fatalf("inode lookup: %v", err)
	}
	if v.Decision != MapDecisionDeny || v.Action != VerdictOpen {
		t.Fatalf("inode val=%+v", v)
	}
}

func TestLoadLiveConnectNotInCatchAll(t *testing.T) {
	maps := testEnforcerMaps(t)
	cp := &CompiledPolicy{
		Version:       1,
		DefaultAction: DefaultActionAllow,
		FailDirection: FailDirectionOpen,
		Live: []CompiledRule{{
			ID: "deny-public-egress", Rationale: "no public", Decision: DecisionDeny,
			Action: "connect", DestIPNotIn: []string{"10.0.0.0/8"}, Specificity: 8,
		}},
	}
	stats, err := LoadLive(cp, maps, PolicyCtrlValues{EnforcementActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if stats.IPAllow != 1 || stats.IPDeny < 2 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestLoadLiveConnectPortNotInCatchAll(t *testing.T) {
	maps := testEnforcerMaps(t)
	cp := &CompiledPolicy{
		Version:       1,
		DefaultAction: DefaultActionAllow,
		FailDirection: FailDirectionOpen,
		Live: []CompiledRule{{
			ID: "deny-weird-ports", Rationale: "ports", Decision: DecisionDeny,
			Action: "connect", DestPortNotIn: []uint16{443, 80}, Specificity: 16,
		}},
	}
	stats, err := LoadLive(cp, maps, PolicyCtrlValues{EnforcementActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if stats.PortAllow != 2 || stats.PortDeny != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestLoadLiveConnectAllowLists(t *testing.T) {
	maps := testEnforcerMaps(t)
	cp := &CompiledPolicy{
		Version:       1,
		DefaultAction: DefaultActionAllow,
		FailDirection: FailDirectionOpen,
		Live: []CompiledRule{{
			ID: "deny-public-egress", Rationale: "no public", Decision: DecisionDeny,
			Action: "connect", DestIPNotIn: []string{"10.0.0.0/8"}, Specificity: 8,
		}, {
			ID: "allow-registry", Rationale: "registry ok", Decision: DecisionAllow,
			Action: "connect", DestIPIn: []string{"10.0.0.0/8"}, DestPortIn: []uint16{443},
			Specificity: 16,
		}},
	}
	stats, err := LoadLive(cp, maps, PolicyCtrlValues{EnforcementActive: false})
	if err != nil {
		t.Fatal(err)
	}
	if stats.IPAllow < 2 || stats.PortAllow != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestLoadLiveExampleBundle(t *testing.T) {
	maps := testEnforcerMaps(t)
	path := filepath.Join("..", "..", "policy.yaml.example")
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := LoadLive(cp, maps, PolicyCtrlValues{})
	if err == nil {
		t.Fatal("expected error for /home/*/.ssh/* glob in example bundle")
	}
	if stats.PathDeny == 0 && stats.IPAllow == 0 {
		t.Fatalf("expected partial stats before error, got %+v err=%v", stats, err)
	}
}

func TestLoadLiveSkipsUIDRules(t *testing.T) {
	maps := testEnforcerMaps(t)
	uid := uint32(1000)
	cp := &CompiledPolicy{
		Version: 1, DefaultAction: DefaultActionAllow, FailDirection: FailDirectionOpen,
		Live: []CompiledRule{{
			ID: "uid-rule", Rationale: "scoped", Decision: DecisionDeny,
			Action: "open", PathIn: []string{"/tmp/*"}, UID: &uid, Specificity: 32,
		}},
	}
	stats, err := LoadLive(cp, maps, PolicyCtrlValues{})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Skipped != 1 || stats.PathDeny != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func mustLPM(prefix string) lpmKey {
	k, err := pathPatternToLPM(prefix)
	if err != nil {
		panic(err)
	}
	return k
}
