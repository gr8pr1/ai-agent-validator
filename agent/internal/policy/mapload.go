package policy

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
)

// pathExpandHomeRoot is the /home directory scanned for "/home/*/.ssh/*" at load time.
var pathExpandHomeRoot = "/home"

// BPF map decision values (must match enforcer.bpf.c).
const (
	MapDecisionAllow = 1
	MapDecisionDeny  = 2
)

// Verdict action codes (must match enforcer.bpf.c VERDICT_*).
const (
	VerdictOpen    = 1
	VerdictUnlink  = 2
	VerdictRename  = 3
	VerdictConnect = 4
	VerdictWrite   = 5
)

// EnforcerMapSet is the writable policy map subset of the enforcer object.
type EnforcerMapSet struct {
	PolicyCtrl *ebpf.Map
	PathDeny   *ebpf.Map
	PathAllow  *ebpf.Map
	InodeDeny  *ebpf.Map
	InodeAllow *ebpf.Map
	IPDeny     *ebpf.Map
	IPAllow    *ebpf.Map
	PortDeny   *ebpf.Map
	PortAllow  *ebpf.Map
}

// PolicyCtrlValues configures the policy_ctrl map during load.
type PolicyCtrlValues struct {
	EnforcementActive bool
	PolicyVersion     uint32
}

// LoadStats counts map entries written by LoadLive.
type LoadStats struct {
	PathDeny   int
	PathAllow  int
	InodeDeny  int
	InodeAllow int
	IPDeny     int
	IPAllow    int
	PortDeny   int
	PortAllow  int
	Skipped    int
}

// lpmKey mirrors struct lpm_key in enforcer.bpf.c.
type lpmKey struct {
	Prefixlen uint32
	Data      [256]byte
}

// pathRule mirrors struct path_rule in enforcer.bpf.c.
type pathRule struct {
	Decision     uint8
	ActionMask   uint8
	RequiresPort uint8
	_            uint8
	RuleIDHash   uint32
	Specificity  uint32
}

func verdictBit(verdict uint8) uint8 {
	if verdict == 0 {
		return 0
	}
	return 1 << (verdict - 1)
}

func mergePathRules(existing, incoming pathRule) pathRule {
	if incoming.Decision != existing.Decision {
		if incoming.Decision == MapDecisionDeny {
			return incoming
		}
		return existing
	}
	switch {
	case incoming.Specificity > existing.Specificity:
		return incoming
	case incoming.Specificity < existing.Specificity:
		return existing
	default:
		out := existing
		out.ActionMask = existing.ActionMask | incoming.ActionMask
		if incoming.RuleIDHash != 0 {
			out.RuleIDHash = incoming.RuleIDHash
		}
		return out
	}
}

func putMergedPathRule(m *ebpf.Map, key lpmKey, incoming pathRule) error {
	var existing pathRule
	if err := m.Lookup(key, &existing); err == nil {
		incoming = mergePathRules(existing, incoming)
	}
	return m.Put(key, incoming)
}

func putMergedInodeRule(m *ebpf.Map, key inodeKey, incoming pathRule) error {
	var existing pathRule
	if err := m.Lookup(key, &existing); err == nil {
		incoming = mergePathRules(existing, incoming)
	}
	return m.Put(key, incoming)
}

// portRule mirrors struct port_rule in enforcer.bpf.c.
type portRule struct {
	Decision   uint8
	Action     uint8
	RequiresIP uint8
	_          uint8
	RuleIDHash uint32
}

// LoadLive clears policy maps and loads enforced (live) rules for kernel evaluation.
// Shadow rules are ignored. Rules with uid/binary/cgroup predicates are skipped and
// recorded in skipped count. Unsupported path globs return an error except
// "/home/*/.ssh/*", which expands to per-user "/home/USER/.ssh/*" prefixes.
func LoadLive(cp *CompiledPolicy, maps EnforcerMapSet, ctrl PolicyCtrlValues) (LoadStats, error) {
	var stats LoadStats
	if cp == nil {
		return stats, fmt.Errorf("compiled policy is nil")
	}
	if err := validateEnforcerMaps(maps); err != nil {
		return stats, err
	}
	if err := clearPolicyMaps(maps); err != nil {
		return stats, err
	}
	for _, rule := range cp.Live {
		if rule.UID != nil || rule.Binary != "" || rule.Cgroup != "" {
			stats.Skipped++
			continue
		}
		verdict, err := actionVerdict(rule.Action)
		if err != nil {
			return stats, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		dec, err := mapDecision(rule.Decision)
		if err != nil {
			return stats, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		hash := RuleIDHash(rule.ID)

		switch rule.Action {
		case "connect":
			n, err := loadConnectRule(rule, maps, verdict, dec, hash)
			if err != nil {
				return stats, fmt.Errorf("rule %q: %w", rule.ID, err)
			}
			stats.IPDeny += n.ipDeny
			stats.IPAllow += n.ipAllow
			stats.PortDeny += n.portDeny
			stats.PortAllow += n.portAllow
		default:
			n, err := loadPathRule(rule, maps, verdict, dec, hash)
			if err != nil {
				return stats, fmt.Errorf("rule %q: %w", rule.ID, err)
			}
			stats.PathDeny += n.pathDeny
			stats.PathAllow += n.pathAllow
			stats.InodeDeny += n.inodeDeny
			stats.InodeAllow += n.inodeAllow
		}
	}
	if err := writePolicyCtrl(cp, maps.PolicyCtrl, ctrl); err != nil {
		return stats, err
	}
	return stats, nil
}

type loadCounts struct {
	pathDeny, pathAllow       int
	inodeDeny, inodeAllow     int
	ipDeny, ipAllow           int
	portDeny, portAllow       int
}

// inodeKey mirrors struct inode_key in enforcer.bpf.c.
type inodeKey struct {
	Ino uint64
	Dev uint32
	_   uint32
}

func loadPathRule(r CompiledRule, maps EnforcerMapSet, verdict, dec uint8, hash uint32) (loadCounts, error) {
	var out loadCounts
	if len(r.PathIn) == 0 {
		return out, fmt.Errorf("path rule has no path_in")
	}
	target := maps.PathDeny
	inodeTarget := maps.InodeDeny
	if dec == MapDecisionAllow {
		target = maps.PathAllow
		inodeTarget = maps.InodeAllow
	}
	val := pathRule{
		Decision:    dec,
		ActionMask:  verdictBit(verdict),
		RuleIDHash:  hash,
		Specificity: uint32(r.Specificity),
	}
	for _, pattern := range r.PathIn {
		expanded, err := expandPathPattern(pattern)
		if err != nil {
			return out, fmt.Errorf("expand path %q: %w", pattern, err)
		}
		for _, p := range expanded {
			key, err := pathPatternToLPM(p)
			if err != nil {
				return out, err
			}
			if err := putMergedPathRule(target, key, val); err != nil {
				return out, fmt.Errorf("put path %q: %w", p, err)
			}
			if dec == MapDecisionAllow {
				out.pathAllow++
			} else {
				out.pathDeny++
			}
			if isExactPathPattern(p) {
				ikey, err := pathToInodeKey(p)
				if err != nil {
					return out, fmt.Errorf("resolve inode for %q: %w", p, err)
				}
				if err := putMergedInodeRule(inodeTarget, ikey, val); err != nil {
					return out, fmt.Errorf("put inode %q: %w", p, err)
				}
				if dec == MapDecisionAllow {
					out.inodeAllow++
				} else {
					out.inodeDeny++
				}
			}
		}
	}
	return out, nil
}

func loadConnectRule(r CompiledRule, maps EnforcerMapSet, verdict, dec uint8, hash uint32) (loadCounts, error) {
	var out loadCounts
	specificity := uint32(r.Specificity)
	requiresPort := uint8(0)
	if len(r.DestPortIn) > 0 || len(r.DestPortNotIn) > 0 {
		requiresPort = 1
	}
	requiresIP := uint8(0)
	if len(r.DestIPIn) > 0 || len(r.DestIPNotIn) > 0 {
		requiresIP = 1
	}
	ipVal := pathRule{
		Decision: dec, ActionMask: verdictBit(verdict), RequiresPort: requiresPort,
		RuleIDHash: hash, Specificity: specificity,
	}
	ipMap := maps.IPDeny
	if dec == MapDecisionAllow {
		ipMap = maps.IPAllow
	}
	portVal := portRule{Decision: dec, Action: verdict, RequiresIP: requiresIP, RuleIDHash: hash}
	portMap := maps.PortDeny
	if dec == MapDecisionAllow {
		portMap = maps.PortAllow
	}

	// dest_ip_in on deny rules → ip_deny; on allow → ip_allow
	for _, cidr := range r.DestIPIn {
		key, err := cidrToLPM(cidr)
		if err != nil {
			return out, err
		}
		if err := ipMap.Put(key, ipVal); err != nil {
			return out, fmt.Errorf("put ip_in %q: %w", cidr, err)
		}
		if dec == MapDecisionAllow {
			out.ipAllow++
		} else {
			out.ipDeny++
		}
	}

	// dest_ip_not_in + deny → allowed CIDRs stored in ip_allow (inverted match at hook time)
	if len(r.DestIPNotIn) > 0 {
		if dec != MapDecisionDeny {
			return out, fmt.Errorf("dest_ip_not_in requires deny decision")
		}
		allowIPVal := pathRule{
			Decision: MapDecisionAllow, ActionMask: verdictBit(verdict), RequiresPort: requiresPort,
			RuleIDHash: hash, Specificity: specificity,
		}
		for _, cidr := range r.DestIPNotIn {
			key, err := cidrToLPM(cidr)
			if err != nil {
				return out, err
			}
			if err := maps.IPAllow.Put(key, allowIPVal); err != nil {
				return out, fmt.Errorf("put ip_not_in allow %q: %w", cidr, err)
			}
			out.ipAllow++
		}
		denyCatch := pathRule{
			Decision: MapDecisionDeny, ActionMask: verdictBit(verdict), RequiresPort: requiresPort,
			RuleIDHash: hash, Specificity: specificity,
		}
		for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
			key, err := cidrToLPM(cidr)
			if err != nil {
				return out, err
			}
			if err := maps.IPDeny.Put(key, denyCatch); err != nil {
				return out, fmt.Errorf("put ip_not_in catch-all %q: %w", cidr, err)
			}
			out.ipDeny++
		}
	}

	for _, port := range r.DestPortIn {
		if err := portMap.Put(port, portVal); err != nil {
			return out, fmt.Errorf("put port_in %d: %w", port, err)
		}
		if dec == MapDecisionAllow {
			out.portAllow++
		} else {
			out.portDeny++
		}
	}

	// dest_port_not_in + deny → allowed ports in port_allow + catch-all deny at port 0
	if len(r.DestPortNotIn) > 0 {
		if dec != MapDecisionDeny {
			return out, fmt.Errorf("dest_port_not_in requires deny decision")
		}
		allowVal := portRule{
			Decision: MapDecisionAllow, Action: verdict,
			RequiresIP: requiresIP, RuleIDHash: hash,
		}
		for _, port := range r.DestPortNotIn {
			if err := maps.PortAllow.Put(port, allowVal); err != nil {
				return out, fmt.Errorf("put port_not_in allow %d: %w", port, err)
			}
			out.portAllow++
		}
		denyCatch := portRule{
			Decision: MapDecisionDeny, Action: verdict,
			RequiresIP: requiresIP, RuleIDHash: hash,
		}
		if err := maps.PortDeny.Put(uint16(0), denyCatch); err != nil {
			return out, fmt.Errorf("put port_not_in catch-all deny: %w", err)
		}
		out.portDeny++
	}

	loaded := out.ipDeny + out.ipAllow + out.portDeny + out.portAllow
	predicates := len(r.DestIPIn) + len(r.DestIPNotIn) + len(r.DestPortIn) + len(r.DestPortNotIn)
	if loaded == 0 && predicates == 0 {
		return out, fmt.Errorf("connect rule has no dest_ip or dest_port predicates")
	}
	return out, nil
}

func validateEnforcerMaps(m EnforcerMapSet) error {
	if m.PolicyCtrl == nil || m.PathDeny == nil || m.PathAllow == nil ||
		m.InodeDeny == nil || m.InodeAllow == nil ||
		m.IPDeny == nil || m.IPAllow == nil || m.PortDeny == nil || m.PortAllow == nil {
		return fmt.Errorf("incomplete enforcer map set")
	}
	return nil
}

func writePolicyCtrl(cp *CompiledPolicy, m *ebpf.Map, ctrl PolicyCtrlValues) error {
	var active uint8
	if ctrl.EnforcementActive {
		active = 1
	}
	var failClosed uint8
	if cp.FailDirection == FailDirectionClosed {
		failClosed = 1
	}
	var defaultDeny uint8
	if cp.DefaultAction == DefaultActionDeny {
		defaultDeny = 1
	}
	val := struct {
		EnforcementActive uint8
		FailClosed        uint8
		DefaultDeny       uint8
		_                 uint8
		PolicyVersion     uint32
	}{
		EnforcementActive: active,
		FailClosed:        failClosed,
		DefaultDeny:       defaultDeny,
		PolicyVersion:     ctrl.PolicyVersion,
	}
	if ctrl.PolicyVersion == 0 {
		val.PolicyVersion = uint32(cp.Version)
	}
	var k uint32
	return m.Put(k, val)
}

func clearPolicyMaps(m EnforcerMapSet) error {
	for _, mp := range []*ebpf.Map{m.PathDeny, m.PathAllow, m.InodeDeny, m.InodeAllow, m.IPDeny, m.IPAllow, m.PortDeny, m.PortAllow} {
		if err := clearMap(mp); err != nil {
			return err
		}
	}
	return nil
}

func clearMap(m *ebpf.Map) error {
	var key, val []byte
	iter := m.Iterate()
	var keys [][]byte
	for iter.Next(&key, &val) {
		kcopy := make([]byte, len(key))
		copy(kcopy, key)
		keys = append(keys, kcopy)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err := m.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func expandPathPattern(pattern string) ([]string, error) {
	if pattern != homeSSHGlobPattern {
		return []string{pattern}, nil
	}
	entries, err := os.ReadDir(pathExpandHomeRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	root := strings.TrimSuffix(pathExpandHomeRoot, "/")
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, root+"/"+e.Name()+"/.ssh/*")
		}
	}
	return out, nil
}

func isExactPathPattern(pattern string) bool {
	if strings.Contains(strings.TrimSuffix(pattern, "/*"), "*") {
		return false
	}
	return !strings.HasSuffix(pattern, "/*")
}

func pathToInodeKey(path string) (inodeKey, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return inodeKey{}, err
	}
	return inodeKey{Ino: st.Ino, Dev: uint32(st.Dev)}, nil
}

func pathPatternToLPM(pattern string) (lpmKey, error) {
	if strings.Contains(strings.TrimSuffix(pattern, "/*"), "*") {
		return lpmKey{}, fmt.Errorf("unsupported path glob %q (only trailing /* supported for kernel load)", pattern)
	}
	var prefix string
	if strings.HasSuffix(pattern, "/*") {
		prefix = strings.TrimSuffix(pattern, "/*")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	} else {
		prefix = pattern
	}
	if prefix == "" {
		return lpmKey{}, fmt.Errorf("empty path pattern")
	}
	if len(prefix) > 256 {
		return lpmKey{}, fmt.Errorf("path pattern too long")
	}
	var k lpmKey
	k.Prefixlen = uint32(len(prefix)) * 8
	copy(k.Data[:], prefix)
	return k, nil
}

func cidrToLPM(cidr string) (lpmKey, error) {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		ip = net.ParseIP(cidr)
		if ip == nil {
			return lpmKey{}, fmt.Errorf("invalid CIDR/IP %q", cidr)
		}
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
		ones := len(ip) * 8
		n = &net.IPNet{IP: ip, Mask: net.CIDRMask(ones, ones)}
	}
	ones, _ := n.Mask.Size()
	ip = n.IP
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	var k lpmKey
	k.Prefixlen = uint32(ones)
	copy(k.Data[:], ip)
	return k, nil
}

func actionVerdict(action string) (uint8, error) {
	switch action {
	case "open":
		return VerdictOpen, nil
	case "write":
		return VerdictWrite, nil
	case "unlink":
		return VerdictUnlink, nil
	case "rename":
		return VerdictRename, nil
	case "connect":
		return VerdictConnect, nil
	default:
		return 0, fmt.Errorf("unsupported action %q for kernel load", action)
	}
}

func mapDecision(decision string) (uint8, error) {
	switch decision {
	case DecisionAllow:
		return MapDecisionAllow, nil
	case DecisionDeny:
		return MapDecisionDeny, nil
	default:
		return 0, fmt.Errorf("unsupported decision %q for kernel load", decision)
	}
}

