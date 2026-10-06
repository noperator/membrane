package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb policy ../ebpf/policy.c -- -Wall -Werror

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// The manifest contains paths and policy, never file contents. Modes match
// inode_policy in policy.c. Selectors are evaluated only before startup.
type policyEntry struct {
	Path     string `json:"path"`
	Mode     uint32 `json:"mode"`
	NoFollow bool   `json:"no_follow,omitempty"`
}

// loadFilesystemPolicy enrolls the startup snapshot before attaching any hooks.
// The loader owns the collection, links, and O_PATH inode references. Orderly
// session shutdown stops the entire workload before calling closePolicy.
func loadFilesystemPolicy(ctx context.Context, cgroupPath, workspace string, entries []policyEntry) (closePolicy func(), retErr error) {
	// Retain every enrolled inode until teardown. Raise only the soft limit,
	// within the existing hard limit; this requires no additional capability.
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return nil, err
	}
	needed := uint64(len(entries)) + 128
	if limit.Cur < needed {
		if limit.Max < needed {
			return nil, fmt.Errorf("filesystem policy needs %d file descriptors; hard limit is %d", needed, limit.Max)
		}
		limit.Cur = needed
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
			return nil, fmt.Errorf("retain snapshot inode references: %w", err)
		}
	}
	spec, err := loadPolicy()
	if err != nil {
		return nil, fmt.Errorf("read filesystem policy BPF: %w", err)
	}
	objects, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load filesystem policy BPF: %w", err)
	}
	var links []link.Link
	var enrolled []int
	closed := false
	closePolicy = func() {
		if closed {
			return
		}
		closed = true
		for _, attachment := range links {
			attachment.Close()
		}
		objects.Close()
		for _, fd := range enrolled {
			unix.Close(fd)
		}
	}
	defer func() {
		if retErr != nil {
			closePolicy()
		}
	}()
	cgroup, err := os.Open(cgroupPath)
	if err != nil {
		return closePolicy, fmt.Errorf("open filesystem policy cgroup: %w", err)
	}
	defer cgroup.Close()
	if err := objects.Maps["policy_cgroup"].Put(uint32(0), uint32(cgroup.Fd())); err != nil {
		return closePolicy, fmt.Errorf("scope filesystem policy: %w", err)
	}
	root, err := unix.Open(workspace, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return closePolicy, fmt.Errorf("open policy workspace: %w", err)
	}
	defer unix.Close(root)
	inodes := objects.Maps["policy_inodes"]
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return closePolicy, err
		}
		if !filepath.IsLocal(entry.Path) || entry.Path == "." || entry.Mode < 1 || entry.Mode > 2 {
			return closePolicy, fmt.Errorf("invalid filesystem policy entry: %+v", entry)
		}
		flags := unix.O_PATH | unix.O_CLOEXEC
		if entry.NoFollow {
			flags |= unix.O_NOFOLLOW
		}
		fd, err := unix.Openat(root, entry.Path, flags, 0)
		if err != nil {
			return closePolicy, fmt.Errorf("enroll filesystem policy path %q: %w", entry.Path, err)
		}
		enrolled = append(enrolled, fd)
		// Multiple configured paths may be hardlinks to the same object.
		// All seed updates precede attachment, so no concurrent BPF updater can
		// race this maximum. There are no runtime policy updates.
		var previous uint32
		if err := inodes.Lookup(uint32(fd), &previous); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return closePolicy, fmt.Errorf("read inode policy for %q: %w", entry.Path, err)
		}
		if entry.Mode > previous {
			if err := inodes.Put(uint32(fd), entry.Mode); err != nil {
				return closePolicy, fmt.Errorf("seed inode policy for %q: %w", entry.Path, err)
			}
		}
	}
	names := make([]string, 0, len(objects.Programs))
	for name := range objects.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return closePolicy, err
		}
		attachment, err := link.AttachLSM(link.LSMOptions{Program: objects.Programs[name]})
		if err != nil {
			return closePolicy, fmt.Errorf("attach mandatory LSM %s: %w", name, err)
		}
		links = append(links, attachment)
	}

	return closePolicy, nil
}
