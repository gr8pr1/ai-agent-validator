// SPDX-License-Identifier: GPL-2.0
//
// P0/P0.5 enrollment-observation BPF program for ebpf-ai-blocker.
//
// Attaches to process lifecycle tracepoints and action syscalls (connect,
// openat, unlinkat, renameat2). Ships records to userspace where enrollment
// (Mode A cgroup / Mode B fingerprint) and lineage propagation are decided.
// This program is observe-only; it never blocks.
//
// Action events are gated by an advisory tagged_pids map written by userspace
// when a process is enrolled or inherits a tag. The proctable remains the
// source of truth for attribution.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EVENT_EXEC 1
#define EVENT_FORK 2
#define EVENT_EXIT 3
#define EVENT_CONNECT 4
#define EVENT_OPEN 5
#define EVENT_UNLINK 6
#define EVENT_RENAME 7

#define MAX_FILENAME 256
#define MAX_ARGV 512
#define MAX_ENV 512
#define MAX_PATH 256
#define EVENT_HEADER_SIZE 64
#define ACTION_DETAIL_SIZE 24
#define EVENT_RECORD_SIZE (EVENT_HEADER_SIZE + MAX_FILENAME + MAX_ARGV + MAX_ENV)
#define ACTION_RECORD_SIZE (EVENT_HEADER_SIZE + ACTION_DETAIL_SIZE + MAX_PATH + MAX_PATH)

#define AF_INET 2
#define AF_INET6 10

// Fixed 64-byte header. Exec records carry filename|argv|env tails; action
// records carry a detail block + up to two path regions (path_len in argv_len,
// path2_len in env_len).
struct enroll_event {
	__u64 timestamp_ns;
	__u64 start_time_ns;
	__u64 cgroup_id;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u8 event_type;
	__u8 _pad0;
	__u16 argv_len;
	__u16 env_len;
	__u16 filename_len;
	char comm[16];
	__u32 _tail_pad;
};

struct action_detail {
	__u8 family;
	__u8 _pad;
	__u16 dport;
	__u32 open_flags;
	__u8 addr[16];
};

struct enroll_buf {
	char data[EVENT_RECORD_SIZE];
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
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct enroll_buf);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

// Advisory pre-filter: userspace writes pid on tag/inherit, deletes on exit.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} tagged_pids SEC(".maps");

static __always_inline void inc_drop(void)
{
	__u32 k = 0;
	__u64 *d = bpf_map_lookup_elem(&drops, &k);
	if (d)
		__sync_fetch_and_add(d, 1);
}

static __always_inline __u16 port_host(__be16 p)
{
	return __builtin_bswap16((__u16)p);
}

static __always_inline int is_tagged_pid(__u32 pid)
{
	return bpf_map_lookup_elem(&tagged_pids, &pid) != NULL;
}

static __always_inline struct enroll_event *
init_action_header(struct enroll_buf *b, __u8 type)
{
	struct enroll_event *e = (struct enroll_event *)b->data;

	__builtin_memset(b->data, 0, EVENT_HEADER_SIZE + ACTION_DETAIL_SIZE);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	e->timestamp_ns = bpf_ktime_get_ns();
	e->start_time_ns = BPF_CORE_READ(task, start_time);
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->pid = pid_tgid >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	e->event_type = type;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

static __always_inline int emit_action(struct enroll_buf *b)
{
	if (bpf_ringbuf_output(&events, b->data, ACTION_RECORD_SIZE, 0) != 0) {
		inc_drop();
		return -1;
	}
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	unsigned int floc = ctx->__data_loc_filename & 0xFFFF;

	__u32 zero = 0;
	struct enroll_buf *b = bpf_map_lookup_elem(&scratch, &zero);
	if (!b)
		return 0;

	struct enroll_event *e = (struct enroll_event *)b->data;
	__builtin_memset(b->data, 0, EVENT_HEADER_SIZE);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	e->timestamp_ns = bpf_ktime_get_ns();
	e->start_time_ns = BPF_CORE_READ(task, start_time);
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->pid = pid_tgid >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	e->event_type = EVENT_EXEC;
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	long flen = bpf_probe_read_kernel_str(b->data + EVENT_HEADER_SIZE,
					      MAX_FILENAME, (char *)ctx + floc);
	if (flen > 0)
		e->filename_len = (flen >= MAX_FILENAME) ? MAX_FILENAME : (__u16)flen;

	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (mm) {
		unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
		unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
		unsigned long env_start = BPF_CORE_READ(mm, env_start);
		unsigned long env_end = BPF_CORE_READ(mm, env_end);

		if (arg_end > arg_start) {
			unsigned long n = arg_end - arg_start;
			if (n > MAX_ARGV)
				n = MAX_ARGV;
			if (bpf_probe_read_user(b->data + EVENT_HEADER_SIZE + MAX_FILENAME,
						n, (void *)arg_start) == 0)
				e->argv_len = (__u16)n;
		}
		if (env_end > env_start) {
			unsigned long n = env_end - env_start;
			if (n > MAX_ENV)
				n = MAX_ENV;
			if (bpf_probe_read_user(b->data + EVENT_HEADER_SIZE + MAX_FILENAME + MAX_ARGV,
						n, (void *)env_start) == 0)
				e->env_len = (__u16)n;
		}
	}

	if (bpf_ringbuf_output(&events, b->data, EVENT_RECORD_SIZE, 0) != 0)
		inc_drop();
	return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	__u32 child_pid = (__u32)ctx->child_pid;
	__u32 parent_pid = (__u32)ctx->parent_pid;
	char child_comm[16];
	bpf_probe_read_kernel(child_comm, sizeof(child_comm), &ctx->child_comm);

	struct enroll_event e;
	__builtin_memset(&e, 0, EVENT_HEADER_SIZE);

	e.timestamp_ns = bpf_ktime_get_ns();
	e.cgroup_id = bpf_get_current_cgroup_id();
	e.pid = child_pid;
	e.ppid = parent_pid;
	e.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	e.event_type = EVENT_FORK;
	__builtin_memcpy(e.comm, child_comm, sizeof(e.comm));

	if (bpf_ringbuf_output(&events, &e, EVENT_HEADER_SIZE, 0) != 0)
		inc_drop();
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	__u32 pid = pid_tgid & 0xFFFFFFFF;
	if (pid != tgid)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 start_time_ns = BPF_CORE_READ(task, start_time);
	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));

	struct enroll_event e;
	__builtin_memset(&e, 0, EVENT_HEADER_SIZE);

	e.timestamp_ns = bpf_ktime_get_ns();
	e.start_time_ns = start_time_ns;
	e.pid = tgid;
	e.event_type = EVENT_EXIT;
	__builtin_memcpy(e.comm, comm, sizeof(e.comm));

	if (bpf_ringbuf_output(&events, &e, EVENT_HEADER_SIZE, 0) != 0)
		inc_drop();
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tagged_pid(pid))
		return 0;

	void *addr_ptr = (void *)ctx->args[1];
	__u16 family = 0;
	if (bpf_probe_read_user(&family, sizeof(family), addr_ptr) != 0)
		return 0;
	if (family != AF_INET && family != AF_INET6)
		return 0;

	__u32 zero = 0;
	struct enroll_buf *b = bpf_map_lookup_elem(&scratch, &zero);
	if (!b)
		return 0;

	init_action_header(b, EVENT_CONNECT);
	struct action_detail *d = (struct action_detail *)(b->data + EVENT_HEADER_SIZE);

	d->family = (__u8)family;

	if (family == AF_INET) {
		struct sockaddr_in_simple sin;
		if (bpf_probe_read_user(&sin, sizeof(sin), addr_ptr) != 0)
			return 0;
		d->dport = port_host(sin.sin_port);
		__builtin_memcpy(d->addr, &sin.sin_addr, 4);
	} else {
		struct sockaddr_in6_simple sin6;
		if (bpf_probe_read_user(&sin6, sizeof(sin6), addr_ptr) != 0)
			return 0;
		d->dport = port_host(sin6.sin6_port);
		__builtin_memcpy(d->addr, sin6.sin6_addr, 16);
	}

	emit_action(b);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tagged_pid(pid))
		return 0;

	const char *path = (const char *)ctx->args[1];
	__u32 flags = (__u32)ctx->args[2];

	__u32 zero = 0;
	struct enroll_buf *b = bpf_map_lookup_elem(&scratch, &zero);
	if (!b)
		return 0;

	struct enroll_event *e = init_action_header(b, EVENT_OPEN);
	struct action_detail *d = (struct action_detail *)(b->data + EVENT_HEADER_SIZE);
	char *path_buf = b->data + EVENT_HEADER_SIZE + ACTION_DETAIL_SIZE;

	d->open_flags = flags;

	long plen = bpf_probe_read_user_str(path_buf, MAX_PATH, path);
	if (plen <= 0)
		return 0;
	e->argv_len = (plen >= MAX_PATH) ? MAX_PATH : (__u16)plen;

	emit_action(b);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tagged_pid(pid))
		return 0;

	const char *path = (const char *)ctx->args[1];

	__u32 zero = 0;
	struct enroll_buf *b = bpf_map_lookup_elem(&scratch, &zero);
	if (!b)
		return 0;

	struct enroll_event *e = init_action_header(b, EVENT_UNLINK);
	char *path_buf = b->data + EVENT_HEADER_SIZE + ACTION_DETAIL_SIZE;

	long plen = bpf_probe_read_user_str(path_buf, MAX_PATH, path);
	if (plen <= 0)
		return 0;
	e->argv_len = (plen >= MAX_PATH) ? MAX_PATH : (__u16)plen;

	emit_action(b);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tagged_pid(pid))
		return 0;

	const char *oldpath = (const char *)ctx->args[1];
	const char *newpath = (const char *)ctx->args[3];

	__u32 zero = 0;
	struct enroll_buf *b = bpf_map_lookup_elem(&scratch, &zero);
	if (!b)
		return 0;

	struct enroll_event *e = init_action_header(b, EVENT_RENAME);
	char *path_buf = b->data + EVENT_HEADER_SIZE + ACTION_DETAIL_SIZE;
	char *path2_buf = path_buf + MAX_PATH;

	long oldlen = bpf_probe_read_user_str(path_buf, MAX_PATH, oldpath);
	if (oldlen <= 0)
		return 0;
	e->argv_len = (oldlen >= MAX_PATH) ? MAX_PATH : (__u16)oldlen;

	long newlen = bpf_probe_read_user_str(path2_buf, MAX_PATH, newpath);
	if (newlen <= 0)
		return 0;
	e->env_len = (newlen >= MAX_PATH) ? MAX_PATH : (__u16)newlen;

	emit_action(b);
	return 0;
}
