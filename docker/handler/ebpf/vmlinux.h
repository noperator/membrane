// SPDX-License-Identifier: GPL-2.0
// Only the Linux types used by probe.c. Kernel fields are relocated by CO-RE
// against runtime BTF; no build-host kernel headers or BTF dump are needed.
#ifndef MEMBRANE_VMLINUX_H
#define MEMBRANE_VMLINUX_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef _Bool bool;
#define true 1
#define false 0

enum bpf_map_type {
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_RINGBUF = 27,
};

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
struct mm_struct {
    unsigned long arg_start;
    unsigned long arg_end;
};
struct task_struct {
    struct task_struct *real_parent;
    int tgid;
    struct mm_struct *mm;
};
struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};
struct file {
    struct path f_path;
    unsigned int f_flags;
};
struct trace_entry {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};
struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
};
#pragma clang attribute pop

// Socket ABI structures are userspace data, not CO-RE kernel fields.
struct sockaddr {
    __u16 sa_family;
    char sa_data[14];
};
struct in_addr { __be32 s_addr; };
struct sockaddr_in {
    __u16 sin_family;
    __be16 sin_port;
    struct in_addr sin_addr;
    __u8 sin_zero[8];
};
struct in6_addr {
    union { __u8 u6_addr8[16]; } in6_u;
};
struct sockaddr_in6 {
    __u16 sin6_family;
    __be16 sin6_port;
    __be32 sin6_flowinfo;
    struct in6_addr sin6_addr;
    __u32 sin6_scope_id;
};
#endif
