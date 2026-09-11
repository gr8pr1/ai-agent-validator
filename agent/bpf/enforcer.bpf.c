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

struct path_buf {
	char data[MAX_PATH];
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
	__type(value, struct path_buf);
} path_scratch SEC(".maps");

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

static __always_inline char *scratch_path(void)
{
	__u32 k = 0;
	struct path_buf *b = bpf_map_lookup_elem(&path_scratch, &k);
	if (!b)
		return NULL;
	return b->data;
}

static __always_inline __u16 port_host(__be16 p)
{
	return __builtin_bswap16(p);
}

static __always_inline int path_len_from_d_path(long ret)
{
	if (ret <= 0)
		return -1;
	if (ret >= MAX_PATH)
		return MAX_PATH - 1;
	return (int)ret;
}

static __always_inline int fill_lpm_key(struct lpm_key *key, const char *path, int len)
{
	if (!key || len <= 0 || len >= MAX_PATH)
		return -1;
	__builtin_memset(key, 0, sizeof(*key));
	key->prefixlen = (__u32)len * 8;
	if (bpf_probe_read_kernel(key->data, MAX_PATH, path) != 0)
		return -1;
	return 0;
}

static __always_inline struct path_rule *path_lpm_lookup(void *map, const char *path, int len)
{
	struct lpm_key key;
	if (fill_lpm_key(&key, path, len) < 0)
		return NULL;
	return bpf_map_lookup_elem(map, &key);
}

static __always_inline int action_matches(__u8 rule_action, __u8 verdict, int write_intent)
{
	if (rule_action == verdict)
		return 1;
	if (verdict == VERDICT_OPEN && rule_action == VERDICT_WRITE && write_intent)
		return 1;
	return 0;
}

static __always_inline int resolve_path_rules(struct path_rule *deny, struct path_rule *allow)
{
	if (deny && deny->decision != MAP_DECISION_DENY)
		deny = NULL;
	if (allow && allow->decision != MAP_DECISION_ALLOW)
		allow = NULL;
	if (!deny && !allow)
		return 0;
	if (deny && allow) {
		if (allow->specificity > deny->specificity)
			return 0;
		return -EPERM;
	}
	if (deny)
		return -EPERM;
	return 0;
}

static __always_inline void emit_deny(__u8 action, __u32 rule_hash, const char *path)
{
	struct deny_verdict *v = bpf_ringbuf_reserve(&deny_verdicts, sizeof(*v), 0);
	if (!v)
		return;
	v->timestamp_ns = bpf_ktime_get_ns();
	v->pid = bpf_get_current_pid_tgid() >> 32;
	v->rule_id_hash = rule_hash;
	v->action = action;
	__builtin_memset(v->path, 0, sizeof(v->path));
	if (path)
		bpf_probe_read_kernel_str(v->path, MAX_PATH, path);
	bpf_ringbuf_submit(v, 0);
}

static __always_inline int enforce_path(const char *path, int len, __u8 verdict, int write_intent)
{
	struct path_rule *deny, *allow;
	int rc;

	if (!path || len <= 0)
		return 0;

	deny = path_lpm_lookup(&path_deny, path, len);
	allow = path_lpm_lookup(&path_allow, path, len);
	if (deny && !action_matches(deny->action, verdict, write_intent))
		deny = NULL;
	if (allow && !action_matches(allow->action, verdict, write_intent))
		allow = NULL;

	rc = resolve_path_rules(deny, allow);
	if (rc == -EPERM) {
		__u32 hash = deny ? deny->rule_id_hash : 0;
		emit_deny(verdict, hash, path);
	}
	return rc;
}

static __always_inline struct path_rule *ip_lpm_lookup(void *map, __u8 *ip, int ip_len)
{
	struct lpm_key key;

	if (!ip || ip_len <= 0 || ip_len > 16)
		return NULL;
	__builtin_memset(&key, 0, sizeof(key));
	key.prefixlen = (__u32)ip_len * 8;
	if (bpf_probe_read_kernel(key.data, 16, ip) != 0)
		return NULL;
	return bpf_map_lookup_elem(map, &key);
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

static __always_inline int enforce_connect(struct sockaddr *address, int addrlen)
{
	__u16 family;
	struct path_rule *dip, *aip;
	struct port_rule *dpt, *apt, *dpt_catch;
	__u8 ip[16] = {};
	__u16 port = 0;
	__u16 port_catch_key = 0;
	int ip_len = 0;

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
			emit_deny(VERDICT_CONNECT, hash, NULL);
			return -EPERM;
		}
	}

	if (dip && !dip->requires_port) {
		if (aip && aip->decision == MAP_DECISION_ALLOW &&
		    aip->specificity >= dip->specificity)
			return 0;
		if (ip_not_in_rule_matches(dip, aip, dip->rule_id_hash)) {
			emit_deny(VERDICT_CONNECT, dip->rule_id_hash, NULL);
			return -EPERM;
		}
	}

	if (dpt_catch && !dpt_catch->requires_ip &&
	    port_not_in_rule_matches(dpt_catch, apt, dpt_catch->rule_id_hash)) {
		emit_deny(VERDICT_CONNECT, dpt_catch->rule_id_hash, NULL);
		return -EPERM;
	}

	if (dip && connect_rule_matches(dip, dpt)) {
		if (aip && aip->specificity > dip->specificity)
			return 0;
		emit_deny(VERDICT_CONNECT, dip->rule_id_hash, NULL);
		return -EPERM;
	}

	if (dpt && dpt != dpt_catch && dpt->decision == MAP_DECISION_DENY &&
	    dpt->action == VERDICT_CONNECT) {
		if (apt && apt->rule_id_hash == dpt->rule_id_hash)
			return 0;
		emit_deny(VERDICT_CONNECT, dpt->rule_id_hash, NULL);
		return -EPERM;
	}

	return 0;
}

static __always_inline int read_path_from_file(struct file *file, char *path_buf)
{
	struct path f_path = BPF_CORE_READ(file, f_path);
	long ret = bpf_d_path(&f_path, path_buf, MAX_PATH);

	return path_len_from_d_path(ret);
}

static __always_inline int read_path_from_path_dentry(const struct path *dir, struct dentry *dentry,
						      char *path_buf)
{
	struct path target;

	target.mnt = BPF_CORE_READ(dir, mnt);
	target.dentry = dentry;
	long ret = bpf_d_path(&target, path_buf, MAX_PATH);

	return path_len_from_d_path(ret);
}

SEC("lsm/file_open")
int BPF_PROG(enforce_file_open, struct file *file)
{
	char *path_buf;
	int len, write_intent;
	__u32 f_flags;
	int rc;

	if (!enforce_gate())
		return 0;

	path_buf = scratch_path();
	if (!path_buf)
		return 0;

	len = read_path_from_file(file, path_buf);
	if (len < 0)
		return 0;

	f_flags = BPF_CORE_READ(file, f_flags);
	write_intent = (f_flags & O_ACCMODE) != 0;

	rc = enforce_path(path_buf, len, VERDICT_OPEN, write_intent);
	return rc;
}

SEC("lsm/path_unlink")
int BPF_PROG(enforce_path_unlink, const struct path *dir, struct dentry *dentry)
{
	char *path_buf;
	int len, rc;

	if (!enforce_gate())
		return 0;

	path_buf = scratch_path();
	if (!path_buf)
		return 0;

	len = read_path_from_path_dentry(dir, dentry, path_buf);
	if (len < 0)
		return 0;

	rc = enforce_path(path_buf, len, VERDICT_UNLINK, 0);
	return rc;
}

SEC("lsm/path_rename")
int BPF_PROG(enforce_path_rename, const struct path *old_dir, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	char *path_buf;
	int len, rc;

	if (!enforce_gate())
		return 0;

	path_buf = scratch_path();
	if (!path_buf)
		return 0;

	len = read_path_from_path_dentry(old_dir, old_dentry, path_buf);
	if (len >= 0) {
		rc = enforce_path(path_buf, len, VERDICT_RENAME, 0);
		if (rc)
			return rc;
	}

	len = read_path_from_path_dentry(new_dir, new_dentry, path_buf);
	if (len < 0)
		return 0;

	rc = enforce_path(path_buf, len, VERDICT_RENAME, 0);
	return rc;
}

SEC("lsm/socket_connect")
int BPF_PROG(enforce_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	if (!enforce_gate())
		return 0;
	return enforce_connect(address, addrlen);
}
