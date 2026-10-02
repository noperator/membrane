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

// loadFilesystemPolicy is the controller-side initial enrollment/attachment
// primitive. All objects are enrolled before workload execution.
//
// Closing controller resources never removes pins. The session owner must first
// terminate the entire workload subtree, then remove the pinned links/maps.
func loadFilesystemPolicy(ctx context.Context, cgroupPath, workspace, pinDir string, entries []policyEntry) (closeController func(), retErr error) {
	// The host checks active BPF LSM before creating this handler. Docker's
	// default AppArmor profile denies securityfs reads inside containers.
	// Loading, attaching, and pinning every mandatory hook below must still
	// succeed before readiness; the host check cannot substitute for them.
	var fs unix.Statfs_t
	if err := unix.Statfs(pinDir, &fs); err != nil {
		return nil, fmt.Errorf("filesystem policy bpffs directory: %w", err)
	}
	if fs.Type != unix.BPF_FS_MAGIC {
		return nil, fmt.Errorf("filesystem policy pin directory %s is not bpffs", pinDir)
	}
	pins, err := os.ReadDir(pinDir)
	if err != nil {
		return nil, fmt.Errorf("read policy pin directory: %w", err)
	}
	if len(pins) != 0 {
		return nil, errors.New("filesystem policy requires a new, empty session pin directory")
	}
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
	closeController = func() {
		if closed {
			return
		}
		closed = true
		// Revoke controller liveness before releasing any inode references.
		revokeErr := objects.Maps["policy_controller"].Put(uint32(0), [16]byte{})
		for _, attachment := range links {
			attachment.Close()
		}
		objects.Close()
		if revokeErr == nil {
			for _, fd := range enrolled {
				unix.Close(fd)
			}
		} // On failure, retain descriptors until process exit (PF_EXITING).
	}
	defer func() {
		if retErr != nil {
			closeController()
		}
	}()
	cgroup, err := os.Open(cgroupPath)
	if err != nil {
		return closeController, fmt.Errorf("open filesystem policy cgroup: %w", err)
	}
	defer cgroup.Close()
	if err := objects.Maps["policy_cgroup"].Put(uint32(0), uint32(cgroup.Fd())); err != nil {
		return closeController, fmt.Errorf("scope filesystem policy: %w", err)
	}
	root, err := unix.Open(workspace, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return closeController, fmt.Errorf("open policy workspace: %w", err)
	}
	defer unix.Close(root)
	inodes := objects.Maps["policy_inodes"]
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return closeController, err
		}
		if !filepath.IsLocal(entry.Path) || entry.Path == "." || entry.Mode < 1 || entry.Mode > 2 {
			return closeController, fmt.Errorf("invalid filesystem policy entry: %+v", entry)
		}
		flags := unix.O_PATH | unix.O_CLOEXEC
		if entry.NoFollow {
			flags |= unix.O_NOFOLLOW
		}
		fd, err := unix.Openat(root, entry.Path, flags, 0)
		if err != nil {
			return closeController, fmt.Errorf("enroll filesystem policy path %q: %w", entry.Path, err)
		}
		enrolled = append(enrolled, fd)
		// Multiple configured paths may be hardlinks to the same object.
		// All seed updates precede attachment, so no concurrent BPF updater can
		// race this maximum. There are no runtime policy updates.
		var previous uint32
		if err := inodes.Lookup(uint32(fd), &previous); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return closeController, fmt.Errorf("read inode policy for %q: %w", entry.Path, err)
		}
		if entry.Mode > previous {
			if err := inodes.Put(uint32(fd), entry.Mode); err != nil {
				return closeController, fmt.Errorf("seed inode policy for %q: %w", entry.Path, err)
			}
		}
	}
	bootstrap, err := os.CreateTemp("", "membrane-controller-*")
	if err != nil {
		return closeController, err
	}
	defer bootstrap.Close()
	defer os.Remove(bootstrap.Name())
	if err := inodes.Put(uint32(bootstrap.Fd()), uint32(3)); err != nil {
		return closeController, err
	}
	for name, object := range objects.Maps {
		if err := object.Pin(filepath.Join(pinDir, name)); err != nil {
			return closeController, fmt.Errorf("pin mandatory map %s: %w", name, err)
		}
	}
	names := make([]string, 0, len(objects.Programs))
	for name := range objects.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return closeController, err
		}
		attachment, err := link.AttachLSM(link.LSMOptions{Program: objects.Programs[name]})
		if err != nil {
			return closeController, fmt.Errorf("attach mandatory LSM %s: %w", name, err)
		}
		links = append(links, attachment)
		if err := attachment.Pin(filepath.Join(pinDir, name)); err != nil {
			return closeController, fmt.Errorf("pin mandatory LSM %s: %w", name, err)
		}
	}
	registration, err := os.Open(bootstrap.Name())
	if err != nil {
		return closeController, fmt.Errorf("register mandatory controller: %w", err)
	}
	registration.Close()
	var owner struct {
		Started uint64
		PID     uint32
		Padding uint32
	}
	if err := objects.Maps["policy_controller"].Lookup(uint32(0), &owner); err != nil || owner.PID == 0 {
		return closeController, fmt.Errorf("mandatory controller registration failed: %v", err)
	}
	return closeController, nil
}
