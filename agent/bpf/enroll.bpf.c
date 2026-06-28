// SPDX-License-Identifier: GPL-2.0
//
// P0 enrollment-observation BPF program for ebpf-ai-blocker.
//
// Attaches to process lifecycle tracepoints and ships a per-process record to
// userspace, where enrollment (Mode A cgroup / Mode B fingerprint) and lineage
// propagation are decided. This program is observe-only; it never blocks.
//
// On exec we capture the resolved binary path plus a bounded prefix of argv and
// of the environment block (read from the new mm). Bounded prefixes are a
// deliberate design choice: a marker past the window is missed, and binary
// identity is the backstop (see architecture.md S5.1).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EVENT_EXEC 1
#define EVENT_FORK 2
#define EVENT_EXIT 3

#define MAX_FILENAME 256
#define MAX_ARGV 512
#define MAX_ENV 512
#define EVENT_HEADER_SIZE 64
#define EVENT_RECORD_SIZE (EVENT_HEADER_SIZE + MAX_FILENAME + MAX_ARGV + MAX_ENV)

// Fixed 64-byte header. Exec records carry a fixed-size tail at constant
// offsets (filename | argv | env); the *_len fields say how many bytes of each
// region are valid. Fork/exit records are header-only (all *_len == 0).
struct enroll_event {
	__u64 timestamp_ns;
	__u64 start_time_ns; // task->start_time, for reuse-safe (pid,start) identity
	__u64 cgroup_id;
	__u32 pid;  // tgid
	__u32 ppid; // parent tgid
	__u32 uid;
	__u8 event_type;
	__u8 _pad0;
	__u16 argv_len;
	__u16 env_len;
	__u16 filename_len;
	char comm[16];
	__u32 _tail_pad;
};

struct enroll_buf {
	char data[EVENT_RECORD_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Per-CPU scratch for the variable-size exec record (too large for the stack).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct enroll_buf);
} scratch SEC(".maps");

// Count of records dropped because the ringbuf was full.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

static __always_inline void inc_drop(void)
{
	__u32 k = 0;
	__u64 *d = bpf_map_lookup_elem(&drops, &k);
	if (d)
		__sync_fetch_and_add(d, 1);
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
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

	// Resolved binary path, from the tracepoint's __data_loc string.
	unsigned int floc = ctx->__data_loc_filename & 0xFFFF;
	long flen = bpf_probe_read_kernel_str(b->data + EVENT_HEADER_SIZE,
					      MAX_FILENAME, (char *)ctx + floc);
	if (flen > 0)
		e->filename_len = (flen >= MAX_FILENAME) ? MAX_FILENAME : (__u16)flen;

	// Bounded prefix of argv and env, read from the freshly-installed mm.
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

	// Fixed-size record: tail regions live at constant offsets so the verifier
	// is happy; userspace slices each region by its *_len.
	if (bpf_ringbuf_output(&events, b->data, EVENT_RECORD_SIZE, 0) != 0)
		inc_drop();
	return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	struct enroll_event *e = bpf_ringbuf_reserve(&events, EVENT_HEADER_SIZE, 0);
	if (!e) {
		inc_drop();
		return 0;
	}
	__builtin_memset(e, 0, EVENT_HEADER_SIZE);

	e->timestamp_ns = bpf_ktime_get_ns();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->pid = (__u32)ctx->child_pid;
	e->ppid = (__u32)ctx->parent_pid;
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	e->event_type = EVENT_FORK;
	__builtin_memcpy(e->comm, ctx->child_comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	__u32 pid = pid_tgid & 0xFFFFFFFF;
	// Only the thread-group leader's exit ends the process; skip thread exits.
	if (pid != tgid)
		return 0;

	struct enroll_event *e = bpf_ringbuf_reserve(&events, EVENT_HEADER_SIZE, 0);
	if (!e) {
		inc_drop();
		return 0;
	}
	__builtin_memset(e, 0, EVENT_HEADER_SIZE);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->timestamp_ns = bpf_ktime_get_ns();
	e->start_time_ns = BPF_CORE_READ(task, start_time);
	e->pid = tgid;
	e->event_type = EVENT_EXIT;
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
