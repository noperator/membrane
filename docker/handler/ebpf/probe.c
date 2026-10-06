// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define EVENT_PROCESS_EXEC   1
#define EVENT_FILE_OPEN      2
#define EVENT_SOCKET_CONNECT 3

#define ARGVBUF  256
#define PATHBUF  256

#define AF_INET   2
#define AF_INET6 10

struct event {
    __u8  type;
    __u32 pid;
    __u32 ppid;
    __u64 timestamp;
    char  comm[16];
    union {
        struct {
            char argv[ARGVBUF];
        } process_exec;
        struct {
            char path[PATHBUF];
            __u32 flags;
        } file_open;
        struct {
            __u16 family;
            __u16 dport;
            __u8  daddr[16];
        } socket_connect;
    };
};

// Keep the wire layout in sync with parseEvent in tracer/main.go.
_Static_assert(sizeof(struct event) == 304, "event size");
_Static_assert(__builtin_offsetof(struct event, timestamp) == 16, "timestamp offset");
_Static_assert(__builtin_offsetof(struct event, process_exec) == 40, "payload offset");
_Static_assert(__builtin_offsetof(struct event, file_open.flags) == 296, "flags offset");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_cgroup SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

static __always_inline int cgroup_allowed(void) {
    return bpf_current_task_under_cgroup(&target_cgroup, 0) == 1;
}

// sched_process_exec tracepoint.
// argv is read from mm->arg_start..arg_end (null-separated in that region).
SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(void *ctx) {
    if (!cgroup_allowed())
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->type = EVENT_PROCESS_EXEC;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);

    // Read argv from mm->arg_start..arg_end. Args are null-separated;
    // Go userspace replaces nulls with spaces.
    unsigned long arg_start = BPF_CORE_READ(task, mm, arg_start);
    unsigned long arg_end   = BPF_CORE_READ(task, mm, arg_end);
    long len = arg_end - arg_start;
    if (len > ARGVBUF - 1)
        len = ARGVBUF - 1;
    if (len > 0)
        bpf_probe_read_user(e->process_exec.argv, len, (void *)arg_start);
    e->process_exec.argv[ARGVBUF - 1] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/security_file_open")
int BPF_PROG(trace_file_open, struct file *file) {
    if (!cgroup_allowed())
        return 0;

    __u32 flags = BPF_CORE_READ(file, f_flags);

    char path[PATHBUF] = {};
    int ret = bpf_d_path(&file->f_path, path, PATHBUF);
    if (ret < 0)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->type = EVENT_FILE_OPEN;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->file_open.flags = flags;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);

    for (int i = 0; i < PATHBUF; i++) {
        e->file_open.path[i] = path[i];
        if (path[i] == '\0')
            break;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// sys_enter_connect records IPv4 and IPv6 connection attempts, including failures.
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_socket_connect(struct trace_event_raw_sys_enter *ctx) {
    if (!cgroup_allowed())
        return 0;

    struct sockaddr sa = {};
    if (bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]) < 0)
        return 0;

    __u16 family = sa.sa_family;
    __u16 dport;
    __u8 daddr[16] = {};

    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        if (bpf_probe_read_user(&sin, sizeof(sin), (void *)ctx->args[1]) < 0)
            return 0;

        dport = bpf_ntohs(sin.sin_port);
        __builtin_memcpy(daddr, &sin.sin_addr.s_addr, 4);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        if (bpf_probe_read_user(&sin6, sizeof(sin6), (void *)ctx->args[1]) < 0)
            return 0;

        dport = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(daddr, &sin6.sin6_addr, sizeof(daddr));
    } else {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->type = EVENT_SOCKET_CONNECT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->socket_connect.family = family;
    e->socket_connect.dport = dport;
    __builtin_memcpy(e->socket_connect.daddr, daddr, sizeof(daddr));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
