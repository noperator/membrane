// SPDX-License-Identifier: GPL-2.0
// Mandatory per-session inode policy. Enrollment and attachment precede workload
// startup; the loader owns all resources until workload teardown.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EACCES 13
#define MAP_PRIVATE 2
#define READONLY 1
#define SEALED 2
#define MAY_WRITE 2
#define MAY_READ 4
#define MAY_EXEC 1
#define PROT_WRITE 2
#define FMODE_WRITE 2
#define O_TRUNC 01000
#define S_IFMT 0170000
#define S_IFDIR 0040000

struct inode_policy {
    __u32 mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} policy_cgroup SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_INODE_STORAGE);
    __uint(map_flags, 1); // BPF_F_NO_PREALLOC
    __type(key, int);
    __type(value, struct inode_policy);
} policy_inodes SEC(".maps");

static __always_inline bool in_session(void) {
    return bpf_current_task_under_cgroup(&policy_cgroup, 0) == 1;
}

static __always_inline __u32 inode_mode(struct inode *inode) {
    if (!inode)
        return 0;
    struct inode_policy *policy = bpf_inode_storage_get(&policy_inodes, inode, 0, 0);
    return policy ? policy->mode : 0;
}

SEC("lsm/file_open")
int BPF_PROG(policy_file_open, struct file *file, int ret) {
    if (ret || !in_session())
        return ret;
    __u32 mode = inode_mode(file->f_inode);
    if (mode == SEALED && (file->f_inode->i_mode & S_IFMT) != S_IFDIR)
        return -EACCES;
    if (mode && ((file->f_mode & FMODE_WRITE) || (file->f_flags & O_TRUNC)))
        return -EACCES;
    return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(policy_file_permission, struct file *file, int mask, int ret) {
    if (ret || !in_session())
        return ret;
    __u32 mode = inode_mode(file->f_inode);
    if (mode == SEALED && (file->f_inode->i_mode & S_IFMT) != S_IFDIR &&
        (mask & (MAY_READ | MAY_WRITE | MAY_EXEC)))
        return -EACCES;
    return mode && (mask & MAY_WRITE) ? -EACCES : 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(policy_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret) {
    if (ret || !in_session() || !file)
        return ret;
    __u32 mode = inode_mode(file->f_inode);
    if (mode == SEALED)
        return -EACCES;
    if (mode && (prot & PROT_WRITE)) {
        // ELF exec loads private writable data segments. They cannot mutate
        // the file; ordinary writable mmap calls remain forbidden.
        struct task_struct *task = bpf_get_current_task_btf();
        if ((flags & 0x0f) == MAP_PRIVATE && BPF_CORE_READ_BITFIELD_PROBED(task, in_execve))
            return 0;
        return -EACCES;
    }
    return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(policy_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret) {
    if (ret || !in_session())
        return ret;
    struct file *file = vma->vm_file;
    if (!file)
        return 0;
    __u32 mode = inode_mode(file->f_inode);
    return mode == SEALED || (mode && (prot & PROT_WRITE)) ? -EACCES : 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(policy_bprm_check_security, struct linux_binprm *bprm, int ret) {
    if (ret || !in_session())
        return ret;
    return inode_mode(bprm->file->f_inode) == SEALED ? -EACCES : 0;
}

SEC("lsm/file_truncate")
int BPF_PROG(policy_file_truncate, struct file *file, int ret) {
    if (ret || !in_session())
        return ret;
    return inode_mode(file->f_inode) ? -EACCES : 0;
}

SEC("lsm/inode_setattr")
int BPF_PROG(policy_inode_setattr, struct dentry *dentry, struct iattr *attr, int ret) {
    if (ret || !in_session())
        return ret;
    return inode_mode(dentry->d_inode) ? -EACCES : 0;
}

SEC("lsm/inode_setxattr")
int BPF_PROG(policy_inode_setxattr, struct mnt_idmap *idmap, struct dentry *dentry,
             const char *name, const void *value, unsigned long size, int flags, int ret) {
    if (ret || !in_session())
        return ret;
    return inode_mode(dentry->d_inode) ? -EACCES : 0;
}

SEC("lsm/inode_removexattr")
int BPF_PROG(policy_inode_removexattr, struct mnt_idmap *idmap,
             struct dentry *dentry, const char *name, int ret) {
    if (ret || !in_session())
        return ret;
    return inode_mode(dentry->d_inode) ? -EACCES : 0;
}

// ACL changes have dedicated hooks on Linux 6.8 and need the same protection
// as other metadata writes even when they bypass inode_setxattr.
SEC("lsm/inode_set_acl")
int BPF_PROG(policy_inode_set_acl, struct mnt_idmap *idmap, struct dentry *dentry,
             const char *name, struct posix_acl *acl, int ret) {
    if (ret || !in_session())
        return ret;
    return inode_mode(dentry->d_inode) ? -EACCES : 0;
}

SEC("lsm/inode_remove_acl")
int BPF_PROG(policy_inode_remove_acl, struct mnt_idmap *idmap,
             struct dentry *dentry, const char *name, int ret) {
    if (ret || !in_session())
        return ret;
    return inode_mode(dentry->d_inode) ? -EACCES : 0;
}

static __always_inline int namespace_write(struct inode *dir, struct dentry *dentry) {
    return inode_mode(dir) || inode_mode(dentry->d_inode) ? -EACCES : 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(policy_inode_unlink, struct inode *dir, struct dentry *dentry, int ret) {
    if (ret || !in_session())
        return ret;
    return namespace_write(dir, dentry);
}

SEC("lsm/inode_rmdir")
int BPF_PROG(policy_inode_rmdir, struct inode *dir, struct dentry *dentry, int ret) {
    if (ret || !in_session())
        return ret;
    return namespace_write(dir, dentry);
}

SEC("lsm/inode_link")
int BPF_PROG(policy_inode_link, struct dentry *old, struct inode *dir,
             struct dentry *entry, int ret) {
    if (ret || !in_session())
        return ret;
    return inode_mode(old->d_inode) ? -EACCES : namespace_write(dir, entry);
}

SEC("lsm/inode_rename")
int BPF_PROG(policy_inode_rename, struct inode *old_dir, struct dentry *old,
             struct inode *new_dir, struct dentry *entry, int ret) {
    if (ret || !in_session())
        return ret;
    return namespace_write(old_dir, old) || namespace_write(new_dir, entry) ? -EACCES : 0;
}

SEC("lsm/inode_create")
int BPF_PROG(policy_inode_create, struct inode *dir, struct dentry *entry,
             unsigned short mode, int ret) {
    if (ret || !in_session())
        return ret;
    return namespace_write(dir, entry);
}

SEC("lsm/inode_mkdir")
int BPF_PROG(policy_inode_mkdir, struct inode *dir, struct dentry *entry,
             unsigned short mode, int ret) {
    if (ret || !in_session())
        return ret;
    return namespace_write(dir, entry);
}

SEC("lsm/inode_symlink")
int BPF_PROG(policy_inode_symlink, struct inode *dir, struct dentry *entry,
             const char *target, int ret) {
    if (ret || !in_session())
        return ret;
    return namespace_write(dir, entry);
}

SEC("lsm/inode_mknod")
int BPF_PROG(policy_inode_mknod, struct inode *dir, struct dentry *entry,
             unsigned short mode, unsigned int device, int ret) {
    if (ret || !in_session())
        return ret;
    return namespace_write(dir, entry);
}

char LICENSE[] SEC("license") = "GPL";
