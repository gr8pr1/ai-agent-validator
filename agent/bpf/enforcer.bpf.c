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

#define VERDICT_OPEN 1
#define VERDICT_UNLINK 2
#define VERDICT_RENAME 3
#define VERDICT_CONNECT 4

// Userspace-owned control plane (P3.3 mapload).
struct policy_ctrl {
	__u8 enforcement_active;
	__u8 fail_closed;
	__u8 default_deny;
	__u8 _pad;
	__u32 policy_version;
};

// LPM key for path and CIDR rules (prefixlen + data).
struct lpm_key {
	__u32 prefixlen;
	__u8 data[MAX_PATH];
};

// Per-path rule metadata stored in LPM trie values.
struct path_rule {
	__u8 decision;   // 1=allow 2=deny
	__u8 _pad[3];
	__u32 rule_id_hash;
	__u32 specificity;
};

// Per-port rule for connect deny/allow lists.
struct port_rule {
	__u8 decision;
	__u8 _pad[3];
	__u32 rule_id_hash;
};

// Deny verdict emitted on separate ringbuf (decision 9B).
struct deny_verdict {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 rule_id_hash;
	__u8 action;
	__u8 _pad[3];
	char path[MAX_PATH];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct policy_ctrl);
} policy_ctrl SEC(".maps");

// Tagged PIDs for Mode B enforcement (mirrored from enroll object in userspace).
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
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} deny_verdicts SEC(".maps");

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

// P3.4 will implement path/port/IP matching and verdict emission.
static __always_inline int enforce_allow(void)
{
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(enforce_file_open, struct file *file)
{
	if (!enforce_gate())
		return enforce_allow();
	return enforce_allow();
}

SEC("lsm/inode_unlink")
int BPF_PROG(enforce_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	if (!enforce_gate())
		return enforce_allow();
	return enforce_allow();
}

SEC("lsm/inode_rename")
int BPF_PROG(enforce_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry)
{
	if (!enforce_gate())
		return enforce_allow();
	return enforce_allow();
}

SEC("lsm/socket_connect")
int BPF_PROG(enforce_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	if (!enforce_gate())
		return enforce_allow();
	return enforce_allow();
}
