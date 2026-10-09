package membrane

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

const (
	policyNormal uint32 = iota
	policyReadonly
	policySealed
)

// filesystemPolicyEntry is a startup snapshot, never a runtime path rule.
// Policy follows enrolled objects; replacement objects remain ordinary.
type filesystemPolicyEntry struct {
	Root     int    `json:"root"`
	Path     string `json:"path"`
	Mode     uint32 `json:"mode"`
	NoFollow bool   `json:"no_follow,omitempty"`
}

func effectiveFilesystemPolicy(cfg *config, workspace, path, relative string, inherited uint32) uint32 {
	if inherited == policySealed || matchesAny(workspace, path, relative, cfg.Sealed) {
		return policySealed
	}
	if inherited == policyReadonly || matchesAny(workspace, path, relative, cfg.Readonly) {
		return policyReadonly
	}
	return policyNormal
}

// resolveFilesystemPolicy walks only selected trees. Explicit restrictions
// inherit independently of the most specific mount's baseline; both use the
// same inode snapshot and manifest, with one entry per canonical path.
func resolveFilesystemPolicy(workspace string, cfg *config, mounts []directoryMount) ([]filesystemPolicyEntry, error) {
	needed := len(cfg.Sealed) != 0 || len(cfg.Readonly) != 0
	for _, mount := range mounts {
		needed = needed || mount.Mode == "ro"
	}
	if !needed {
		return nil, nil
	}
	byPath := make(map[string]filesystemPolicyEntry)
	directories := make(map[string]uint32)
	var links []string
	for root, mount := range mounts {
		// An ancestor walk already includes this subtree, with its inherited
		// selectors. Do not walk overlapping roots a second time.
		covered := false
		for other, ancestor := range mounts {
			relative, err := filepath.Rel(ancestor.Path, mount.Path)
			if other != root && err == nil && filepath.IsLocal(relative) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		err := filepath.WalkDir(mount.Path, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return fmt.Errorf("enumerate filesystem policy: %w", walkErr)
			}
			relative, err := filepath.Rel(mount.Path, path)
			if err != nil {
				return err
			}
			// Include the selected root directory itself, but no unselected
			// host ancestors, when matching unanchored component sequences.
			mode := effectiveFilesystemPolicy(cfg, workspace, path,
				filepath.Join(filepath.Base(mount.Path), relative), directories[filepath.Dir(path)])
			if d.IsDir() {
				directories[path] = mode
			}
			entry := filesystemPolicyEntry{Root: root, Path: relative, Mode: mode, NoFollow: d.Type()&os.ModeSymlink != 0}
			for nested, selected := range mounts {
				rel, err := filepath.Rel(selected.Path, path)
				if err == nil && filepath.IsLocal(rel) && len(selected.Path) > len(mounts[entry.Root].Path) {
					entry.Root, entry.Path = nested, rel
				}
			}
			// Keep ordinary objects too: protected symlink targets must be in
			// this snapshot, and directory targets protect their descendants.
			byPath[path] = entry
			if entry.NoFollow && (mode != policyNormal || mounts[entry.Root].Mode == "ro") {
				links = append(links, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	// WalkDir never follows directory symlinks. Resolve protected links only
	// after enumerating the selected trees, and propagate explicit restrictions
	// through that existing snapshot rather than traversing an alias anew.
	for len(links) != 0 {
		path := links[0]
		links = links[1:]
		entry := byPath[path]
		target, err := filepath.EvalSymlinks(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("resolve protected symlink %q: %w", path, err)
		}
		if _, ok := byPath[target]; !ok {
			return nil, fmt.Errorf("protected symlink %q must resolve within a selected directory's startup snapshot", path)
		}
		// A readonly mount protects the link itself; the target's own mount
		// determines its baseline. Only explicit selectors propagate here.
		if entry.Mode == policyNormal {
			continue
		}
		_, directory := directories[target]
		for candidate, next := range byPath {
			relative, err := filepath.Rel(target, candidate)
			if candidate != target && (!directory || err != nil || !filepath.IsLocal(relative)) {
				continue
			}
			if next.Mode >= entry.Mode {
				continue
			}
			next.Mode = entry.Mode
			byPath[candidate] = next
			if next.NoFollow {
				links = append(links, candidate)
			}
		}
	}
	var entries []filesystemPolicyEntry
	for _, entry := range byPath {
		if mounts[entry.Root].Mode == "ro" && entry.Mode < policyReadonly {
			entry.Mode = policyReadonly
		}
		if entry.Mode != policyNormal {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Root != entries[j].Root {
			return entries[i].Root < entries[j].Root
		}
		return entries[i].Path < entries[j].Path
	})
	return entries, nil
}
