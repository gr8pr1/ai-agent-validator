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
	if v.Decision != MapDecisionDeny || v.ActionMask != verdictBit(VerdictOpen) {
		t.Fatalf("val=%+v", v)
	}
	ikey, err := pathToInodeKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := maps.InodeDeny.Lookup(ikey, &v); err != nil {
		t.Fatalf("inode lookup: %v", err)
	}
	if v.Decision != MapDecisionDeny || v.ActionMask != verdictBit(VerdictOpen) {
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

func TestLoadLiveLocalhostCarveOut(t *testing.T) {
	maps := testEnforcerMaps(t)
	cp := &CompiledPolicy{
		Version:       1,
		DefaultAction: DefaultActionAllow,
		FailDirection: FailDirectionOpen,
		Live: []CompiledRule{{
			ID: "deny-public-egress", Rationale: "no public", Decision: DecisionDeny,
			Action: "connect",
			DestIPNotIn: []string{
				"10.0.0.0/8", "127.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12",
			},
			Specificity: 16,
		}, {
			ID: "allow-localhost", Rationale: "loopback ok", Decision: DecisionAllow,
			Action: "connect", DestIPIn: []string{"127.0.0.0/8"}, Specificity: 8,
		}},
	}
	stats, err := LoadLive(cp, maps, PolicyCtrlValues{EnforcementActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if stats.IPAllow < 5 {
		t.Fatalf("expected private-range allow entries, stats=%+v", stats)
	}
	allow, err := lookupIPRule(maps.IPAllow, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if allow.Decision != MapDecisionAllow {
		t.Fatalf("127.0.0.1 allow decision=%d", allow.Decision)
	}
	deny, err := lookupIPRule(maps.IPDeny, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if deny.Decision != MapDecisionDeny {
		t.Fatalf("8.8.8.8 deny decision=%d", deny.Decision)
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

func TestExpandPathPatternHomeSSH(t *testing.T) {
	home := t.TempDir()
	orig := pathExpandHomeRoot
	pathExpandHomeRoot = home
	t.Cleanup(func() { pathExpandHomeRoot = orig })

	if err := os.MkdirAll(filepath.Join(home, "alice", ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "bob"), []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := expandPathPattern("/home/*/.ssh/*")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, "alice", ".ssh") + "/*"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %v want [%s]", got, want)
	}
	passthrough, err := expandPathPattern("/etc/shadow")
	if err != nil || len(passthrough) != 1 || passthrough[0] != "/etc/shadow" {
		t.Fatalf("passthrough=%v err=%v", passthrough, err)
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
	if err != nil {
		t.Fatalf("load example bundle: %v", err)
	}
	if stats.PathDeny == 0 && stats.IPAllow == 0 {
		t.Fatalf("expected map entries, got %+v", stats)
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

func TestLoadPathRuleMergesActionMask(t *testing.T) {
	maps := testEnforcerMaps(t)
	cp := &CompiledPolicy{
		Version:       1,
		DefaultAction: DefaultActionAllow,
		FailDirection: FailDirectionOpen,
		Live: []CompiledRule{
			{
				ID: "deny-etc-write", Rationale: "no etc write", Decision: DecisionDeny,
				Action: "write", PathIn: []string{"/etc/*"}, Specificity: 8,
			},
			{
				ID: "deny-etc-unlink", Rationale: "no etc unlink", Decision: DecisionDeny,
				Action: "unlink", PathIn: []string{"/etc/*"}, Specificity: 8,
			},
			{
				ID: "deny-etc-rename", Rationale: "no etc rename", Decision: DecisionDeny,
				Action: "rename", PathIn: []string{"/etc/*"}, Specificity: 8,
			},
		},
	}
	if _, err := LoadLive(cp, maps, PolicyCtrlValues{EnforcementActive: true}); err != nil {
		t.Fatal(err)
	}
	var v pathRule
	key := mustLPM("/etc/shadow")
	if err := maps.PathDeny.Lookup(key, &v); err != nil {
		t.Fatal(err)
	}
	want := verdictBit(VerdictWrite) | verdictBit(VerdictUnlink) | verdictBit(VerdictRename)
	if v.ActionMask != want {
		t.Fatalf("ActionMask=%#x want %#x", v.ActionMask, want)
	}
}

func mustLPM(prefix string) lpmKey {
	k, err := pathPatternToLPM(prefix)
	if err != nil {
		panic(err)
	}
	return k
}

func lookupIPRule(m *ebpf.Map, ip string) (pathRule, error) {
	k, err := cidrToLPM(ip + "/32")
	if err != nil {
		return pathRule{}, err
	}
	var v pathRule
	if err := m.Lookup(k, &v); err != nil {
		return pathRule{}, err
	}
	return v, nil
}
