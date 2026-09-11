// SPDX-License-Identifier: GPL-2.0
//
// P3 enforcement BPF program for ebpf-ai-blocker.
//
// LSM hooks return -EPERM for tagged agent processes when a live deny rule
// matches. Shadow rules are evaluated in userspace only (P2).
//
// Requires CONFIG_BPF_LSM and boot param lsm=...,bpf.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_PATH 256
#define EPERM 13

#define AF_INET 2
#define AF_INET6 10

#define O_ACCMODE 00000003

#define VERDICT_OPEN 1
#define VERDICT_UNLINK 2
#define VERDICT_RENAME 3
#define VERDICT_CONNECT 4
#define VERDICT_WRITE 5

#define MAP_DECISION_ALLOW 1
#define MAP_DECISION_DENY 2

struct policy_ctrl {
	__u8 enforcement_active;
	__u8 fail_closed;
	__u8 default_deny;
	__u8 _pad;
	__u32 policy_version;
};

struct lpm_key {
	__u32 prefixlen;
	__u8 data[MAX_PATH];
};

struct path_rule {
	__u8 decision;
	__u8 action;
	__u8 requires_port;
	__u8 _pad;
	__u32 rule_id_hash;
	__u32 specificity;
};

struct port_rule {
	__u8 decision;
	__u8 action;
	__u8 requires_ip;
	__u8 _pad;
	__u32 rule_id_hash;
};

struct deny_verdict {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 rule_id_hash;
	__u8 action;
	__u8 _pad[3];
	char path[MAX_PATH];
};

struct pending_open {
	__u16 len;
	__u16 open_flags;
	char path[MAX_PATH];
};

struct pending_connect {
	__u16 port;
	__u8 ip_len;
	__u8 _pad;
	__u8 ip[16];
};

struct inode_key {
	__u64 ino;
	__u32 dev;
	__u32 _pad;
};

struct sockaddr_in_simple {
	__u16 sin_family;
	__be16 sin_port;
	__be32 sin_addr;
};

struct sockaddr_in6_simple {
	__u16 sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	__u8 sin6_addr[16];
	__u32 sin6_scope_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct policy_ctrl);
} policy_ctrl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} tagged_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct pending_open);
} pending_open_paths SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct pending_connect);
} pending_connects SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pending_open);
} pending_open_cpu SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pending_connect);
} pending_connect_cpu SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct inode_key);
	__type(value, struct path_rule);
} inode_deny SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, struct inode_key);
	__type(value, struct path_rule);
} inode_allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 512);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, struct path_rule);
} path_deny SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, struct path_rule);
} path_allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, struct path_rule);
} ip_deny SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);
	__type(value, struct port_rule);
} port_deny SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, struct path_rule);
} ip_allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);
	__type(value, struct port_rule);
} port_allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} deny_verdicts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct lpm_key);
} lpm_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[MAX_PATH]);
} path_scratch SEC(".maps");

#define STAT_FILE_OPEN    0
#define STAT_GATE_PASS    1
#define STAT_OPENAT_FMOD  2
#define STAT_OPENAT_DENY  3
#define STAT_CONNECT_FMOD 4
#define STAT_CONNECT_DENY 5
#define STAT_ENFORCE_MAX  6

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_ENFORCE_MAX);
	__type(key, __u32);
	__type(value, __u64);
} enforce_stats SEC(".maps");

static __always_inline int is_enforcement_active(void)
{
	__u32 k = 0;
	struct policy_ctrl *c = bpf_map_lookup_elem(&policy_ctrl, &k);
	if (!c)
		return 0;
	return c->enforcement_active != 0;
}

static __always_inline int is_tagged_pid(__u32 pid)
{
	return bpf_map_lookup_elem(&tagged_pids, &pid) != NULL;
}

static __always_inline int enforce_gate(void)
{
	if (!is_enforcement_active())
		return 0;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tagged_pid(pid))
		return 0;
	return 1;
}

static __always_inline struct lpm_key *scratch_lpm_key(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&lpm_scratch, &k);
}

static __always_inline char *scratch_path_buf(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&path_scratch, &k);
}

static __always_inline int valid_path_len(__u16 len)
{
	return len > 0 && len < MAX_PATH;
}

static __always_inline int copy_path_bounded(char *dst, const char *src, __u16 src_len)
{
	if (!dst || !src || !valid_path_len(src_len))
		return -1;
	if (bpf_probe_read_kernel(dst, MAX_PATH - 1, src) != 0)
		return -1;
	return src_len;
}

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&enforce_stats, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline __u16 port_host(__be16 p)
{
	return __builtin_bswap16(p);
}

static __always_inline struct path_rule *path_lpm_lookup(void *map, const char *path, int len)
{
	struct lpm_key *key = scratch_lpm_key();

	if (!key || !path || len <= 0 || len >= MAX_PATH)
		return NULL;
	__builtin_memset(key, 0, sizeof(*key));
	key->prefixlen = (__u32)len * 8;
	if (bpf_probe_read_kernel(key->data, MAX_PATH - 1, path) != 0)
		return NULL;
	return bpf_map_lookup_elem(map, key);
}

static __always_inline int action_matches(__u8 rule_action, __u8 verdict, int write_intent)
{
	if (rule_action == verdict)
		return 1;
	if (verdict == VERDICT_OPEN && rule_action == VERDICT_WRITE && write_intent)
		return 1;
	return 0;
}

static __always_inline void emit_deny(__u8 action, __u32 rule_hash,
				      const char *path, int path_len)
{
	struct deny_verdict *v = bpf_ringbuf_reserve(&deny_verdicts, sizeof(*v), 0);

	if (!v)
		return;
	v->timestamp_ns = bpf_ktime_get_ns();
	v->pid = bpf_get_current_pid_tgid() >> 32;
	v->rule_id_hash = rule_hash;
	v->action = action;
	__builtin_memset(v->path, 0, sizeof(v->path));
	if (path && path_len > 0 && path_len < MAX_PATH)
		bpf_probe_read_kernel(v->path, MAX_PATH - 1, path);
	bpf_ringbuf_submit(v, 0);
}

static __always_inline int enforce_open_verdict(struct path_rule *deny_rule,
						struct path_rule *allow_rule,
						__u8 verdict, int write_intent,
						const char *path, int path_len)
{
	int deny_match = 0;
	__u32 deny_spec = 0;
	__u32 deny_hash = 0;

	if (deny_rule && deny_rule->decision == MAP_DECISION_DENY &&
	    action_matches(deny_rule->action, verdict, write_intent)) {
		deny_match = 1;
		deny_spec = deny_rule->specificity;
		deny_hash = deny_rule->rule_id_hash;
	}

	if (allow_rule && allow_rule->decision == MAP_DECISION_ALLOW &&
	    action_matches(allow_rule->action, verdict, write_intent) &&
	    allow_rule->specificity > deny_spec)
		return 0;

	if (deny_match) {
		emit_deny(verdict, deny_hash, path, path_len);
		return -EPERM;
	}
	return 0;
}

static __always_inline struct path_rule *inode_rule_lookup(void *map, struct file *file)
{
	struct inode *inode;
	struct inode_key ikey = {};

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return NULL;
	ikey.ino = BPF_CORE_READ(inode, i_ino);
	ikey.dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);
	return bpf_map_lookup_elem(map, &ikey);
}

static __always_inline int enforce_path(char *path, int len, __u8 verdict, int write_intent)
{
	struct path_rule *deny_rule, *allow_rule;

	if (!path || len <= 0 || len >= MAX_PATH)
		return 0;

	deny_rule = path_lpm_lookup(&path_deny, path, len);
	allow_rule = path_lpm_lookup(&path_allow, path, len);
	return enforce_open_verdict(deny_rule, allow_rule, verdict, write_intent, path, len);
}

static __always_inline struct path_rule *ip_lpm_lookup(void *map, __u8 *ip, int ip_len)
{
	struct lpm_key *key = scratch_lpm_key();
	int i;

	if (!key || !ip || ip_len <= 0 || ip_len > 16)
		return NULL;
	__builtin_memset(key, 0, sizeof(*key));
	key->prefixlen = (__u32)ip_len * 8;
	for (i = 0; i < 16; i++) {
		if (i >= ip_len)
			break;
		key->data[i] = ip[i];
	}
	return bpf_map_lookup_elem(map, key);
}

static __always_inline int connect_rule_matches(struct path_rule *ip_rule, struct port_rule *port_rule)
{
	if (!ip_rule || ip_rule->action != VERDICT_CONNECT)
		return 0;
	if (!ip_rule->requires_port)
		return 1;
	return port_rule && port_rule->action == VERDICT_CONNECT &&
	       port_rule->rule_id_hash == ip_rule->rule_id_hash;
}

static __always_inline int ip_not_in_rule_matches(struct path_rule *dip, struct path_rule *aip, __u32 hash)
{
	if (!dip || dip->rule_id_hash != hash || dip->decision != MAP_DECISION_DENY)
		return 0;
	if (aip && aip->rule_id_hash == hash)
		return 0;
	return 1;
}

static __always_inline int port_not_in_rule_matches(struct port_rule *dpt, struct port_rule *apt, __u32 hash)
{
	if (!dpt || dpt->rule_id_hash != hash || dpt->decision != MAP_DECISION_DENY)
		return 0;
	if (apt && apt->rule_id_hash == hash)
		return 0;
	return 1;
}

static __always_inline int enforce_connect_parsed(__u8 *ip, int ip_len, __u16 port)
{
	struct path_rule *dip, *aip;
	struct port_rule *dpt, *apt, *dpt_catch;
	__u16 port_catch_key = 0;

	if (!ip || ip_len <= 0)
		return 0;

	dip = ip_lpm_lookup(&ip_deny, ip, ip_len);
	aip = ip_lpm_lookup(&ip_allow, ip, ip_len);
	dpt = bpf_map_lookup_elem(&port_deny, &port);
	apt = bpf_map_lookup_elem(&port_allow, &port);
	dpt_catch = bpf_map_lookup_elem(&port_deny, &port_catch_key);

	if (aip && connect_rule_matches(aip, apt))
		return 0;

	if (dip && dpt_catch && dip->rule_id_hash == dpt_catch->rule_id_hash &&
	    dip->requires_port && dpt_catch->requires_ip) {
		__u32 hash = dip->rule_id_hash;
		if (ip_not_in_rule_matches(dip, aip, hash) &&
		    port_not_in_rule_matches(dpt_catch, apt, hash)) {
			emit_deny(VERDICT_CONNECT, hash, NULL, 0);
			return -EPERM;
		}
	}

	if (dip && !dip->requires_port) {
		if (aip && aip->decision == MAP_DECISION_ALLOW &&
		    aip->action == VERDICT_CONNECT && !aip->requires_port)
			return 0;
		if (ip_not_in_rule_matches(dip, aip, dip->rule_id_hash)) {
			emit_deny(VERDICT_CONNECT, dip->rule_id_hash, NULL, 0);
			return -EPERM;
		}
	}

	if (dpt_catch && !dpt_catch->requires_ip &&
	    port_not_in_rule_matches(dpt_catch, apt, dpt_catch->rule_id_hash)) {
		emit_deny(VERDICT_CONNECT, dpt_catch->rule_id_hash, NULL, 0);
		return -EPERM;
	}

	if (dip && connect_rule_matches(dip, dpt)) {
		if (aip && aip->specificity > dip->specificity)
			return 0;
		emit_deny(VERDICT_CONNECT, dip->rule_id_hash, NULL, 0);
		return -EPERM;
	}

	if (dpt && dpt != dpt_catch && dpt->decision == MAP_DECISION_DENY &&
	    dpt->action == VERDICT_CONNECT) {
		if (apt && apt->rule_id_hash == dpt->rule_id_hash)
			return 0;
		emit_deny(VERDICT_CONNECT, dpt->rule_id_hash, NULL, 0);
		return -EPERM;
	}

	return 0;
}

static __always_inline int enforce_connect(struct sockaddr *address, int addrlen)
{
	__u16 family;
	__u8 ip[16] = {};
	__u16 port = 0;
	int ip_len = 0;

	(void)addrlen;
	if (bpf_probe_read_user(&family, sizeof(family), address) != 0)
		return 0;

	if (family == AF_INET) {
		struct sockaddr_in_simple sin;

		if (bpf_probe_read_user(&sin, sizeof(sin), address) != 0)
			return 0;
		port = port_host(sin.sin_port);
		if (bpf_probe_read_user(ip, 4, &sin.sin_addr) != 0)
			return 0;
		ip_len = 4;
	} else if (family == AF_INET6) {
		struct sockaddr_in6_simple sin6;

		if (bpf_probe_read_user(&sin6, sizeof(sin6), address) != 0)
			return 0;
		port = port_host(sin6.sin6_port);
		if (bpf_probe_read_user(ip, 16, sin6.sin6_addr) != 0)
			return 0;
		ip_len = 16;
	} else {
		return 0;
	}

	return enforce_connect_parsed(ip, ip_len, port);
}

static __always_inline __u16 cgroup_user_port(__u32 user_port)
{
	return port_host((__be16)(user_port >> 16));
}

static __always_inline int cgroup_connect_action(__u8 *ip, int ip_len, __u16 port)
{
	int rc = enforce_connect_parsed(ip, ip_len, port);

	if (rc) {
		stat_inc(STAT_CONNECT_DENY);
		return 1;
	}
	return 0;
}

static __always_inline __u32 u32_ntoh(__u32 be)
{
	return __builtin_bswap32(be);
}

static __always_inline void be32_to_ip_bytes(__u8 *ip, int off, __u32 be)
{
	__u32 a = u32_ntoh(be);

	ip[off] = (a >> 24) & 0xff;
	ip[off + 1] = (a >> 16) & 0xff;
	ip[off + 2] = (a >> 8) & 0xff;
	ip[off + 3] = a & 0xff;
}

// Cgroup connect hooks must read bpf_sock_addr fields in the SEC function itself,
// without loops or passing ctx into helpers (verifier rejects on 6.8).
SEC("cgroup/connect4")
int enforce_cgroup_connect4(struct bpf_sock_addr *ctx)
{
	__u8 ip[4];
	__u32 ip4;
	__u32 user_port;

	ip4 = ctx->user_ip4;
	user_port = ctx->user_port;
	if (!enforce_gate())
		return 0;
	// Hook can run before user_ip4 is populated; do not deny on empty target.
	if (!ip4)
		return 0;

	be32_to_ip_bytes(ip, 0, ip4);
	return cgroup_connect_action(ip, 4, cgroup_user_port(user_port));
}

SEC("cgroup/connect6")
int enforce_cgroup_connect6(struct bpf_sock_addr *ctx)
{
	__u8 ip[16];
	__u32 w0, w1, w2, w3;
	__u32 user_port;

	w0 = ctx->user_ip6[0];
	w1 = ctx->user_ip6[1];
	w2 = ctx->user_ip6[2];
	w3 = ctx->user_ip6[3];
	user_port = ctx->user_port;
	if (!enforce_gate())
		return 0;
	if (!w0 && !w1 && !w2 && !w3)
		return 0;

	be32_to_ip_bytes(ip, 0, w0);
	be32_to_ip_bytes(ip, 4, w1);
	be32_to_ip_bytes(ip, 8, w2);
	be32_to_ip_bytes(ip, 12, w3);
	return cgroup_connect_action(ip, 16, cgroup_user_port(user_port));
}

// file_open: inode deny/allow only when bpf LSM is active. Path rules are enforced
// by fmod_ret/__x64_sys_openat (primary on hosts without bpf in the LSM stack).
SEC("lsm/file_open")
int BPF_PROG(enforce_file_open, struct file *file)
{
	struct path_rule *deny_rule, *allow_rule;
	__u32 f_flags;
	int write_intent;

	stat_inc(STAT_FILE_OPEN);
	if (!enforce_gate())
		return 0;
	stat_inc(STAT_GATE_PASS);

	f_flags = BPF_CORE_READ(file, f_flags);
	write_intent = (f_flags & O_ACCMODE) != 0;

	deny_rule = inode_rule_lookup(&inode_deny, file);
	allow_rule = inode_rule_lookup(&inode_allow, file);
	return enforce_open_verdict(deny_rule, allow_rule, VERDICT_OPEN, write_intent, NULL, 0);
}

// Unlink/rename path resolution deferred; open/connect enforcement covers v1 bundle.
SEC("lsm/path_unlink")
int BPF_PROG(enforce_path_unlink, const struct path *dir, struct dentry *dentry)
{
	(void)dir;
	(void)dentry;
	if (!enforce_gate())
		return 0;
	return 0;
}

SEC("lsm/path_rename")
int BPF_PROG(enforce_path_rename, const struct path *old_dir, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	(void)old_dir;
	(void)old_dentry;
	(void)new_dir;
	(void)new_dentry;
	(void)flags;
	if (!enforce_gate())
		return 0;
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(enforce_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	if (!enforce_gate())
		return 0;
	return enforce_connect(address, addrlen);
}

// Syscall fmod_ret hooks block at entry and do not depend on bpf being in the
// active LSM list (AttachLSM can succeed while hooks never run without lsm=...,bpf).
// Paths and connect targets are staged by enroll sys_enter_* tracepoints (same pid
// key) which run before these syscall wrappers; no PT_REGS or user reads here.
#if defined(__TARGET_ARCH_x86) || defined(bpf_target_x86)
static __always_inline int enforce_openat_from_pending(__u32 pid)
{
	struct pending_open *po;
	char *path;
	int write_intent, rc, len;
	__u32 k = 0;

	po = bpf_map_lookup_elem(&pending_open_paths, &pid);
	if (!po || !valid_path_len(po->len))
		po = bpf_map_lookup_elem(&pending_open_cpu, &k);
	path = scratch_path_buf();
	if (!po || !path || !valid_path_len(po->len))
		return 0;

	len = copy_path_bounded(path, po->path, po->len);
	if (len < 0)
		return 0;

	write_intent = (po->open_flags & O_ACCMODE) != 0;
	rc = enforce_path(path, len, VERDICT_OPEN, write_intent);
	if (rc)
		stat_inc(STAT_OPENAT_DENY);
	return rc;
}

static __always_inline int enforce_connect_from_pending(__u32 pid)
{
	struct pending_connect *pc;
	int rc, ip_len;
	__u32 k = 0;

	pc = bpf_map_lookup_elem(&pending_connects, &pid);
	if (!pc)
		pc = bpf_map_lookup_elem(&pending_connect_cpu, &k);
	if (!pc)
		return 0;
	ip_len = pc->ip_len;
	if (ip_len != 4 && ip_len != 16)
		return 0;

	rc = enforce_connect_parsed(pc->ip, ip_len, pc->port);
	if (rc)
		stat_inc(STAT_CONNECT_DENY);
	return rc;
}

SEC("fmod_ret/__x64_sys_openat")
int BPF_PROG(enforce_openat_entry)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	stat_inc(STAT_OPENAT_FMOD);
	if (!enforce_gate())
		return 0;
	return enforce_openat_from_pending(pid);
}

SEC("fmod_ret/__x64_sys_connect")
int BPF_PROG(enforce_connect_entry)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	stat_inc(STAT_CONNECT_FMOD);
	if (!enforce_gate())
		return 0;
	return enforce_connect_from_pending(pid);
}
#endif
