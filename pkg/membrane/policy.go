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
	Path     string `json:"path"`
	Mode     uint32 `json:"mode"`
	NoFollow bool   `json:"no_follow,omitempty"`
}

func effectiveFilesystemPolicy(cfg *config, relative, name string, inherited uint32) uint32 {
	if inherited == policySealed || matchesAny(relative, name, cfg.Ignore) {
		return policySealed
	}
	if inherited == policyReadonly || matchesAny(relative, name, cfg.Readonly) {
		return policyReadonly
	}
	return policyNormal
}

// resolveFilesystemPolicy reuses the existing filename/workspace-relative
// filepath.Match semantics, including trailing-slash normalization. Overlapping
// selectors combine by maximum policy, and every protected directory descendant
// is included rather than only the directory's mount path.
func resolveFilesystemPolicy(workspace string, cfg *config) ([]filesystemPolicyEntry, error) {
	if len(cfg.Ignore) == 0 && len(cfg.Readonly) == 0 {
		return nil, nil
	}
	var entries []filesystemPolicyEntry
	directories := map[string]uint32{".": policyNormal}
	err := filepath.WalkDir(workspace, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("enumerate filesystem policy: %w", walkErr)
		}
		relative, err := filepath.Rel(workspace, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		mode := effectiveFilesystemPolicy(cfg, relative, entry.Name(), directories[filepath.Dir(relative)])
		if mode != policyNormal {
			entries = append(entries, filesystemPolicyEntry{Path: relative, Mode: mode})
		}
		if entry.IsDir() {
			directories[relative] = mode
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Enroll protected links themselves for namespace/metadata operations and
	// their resolved targets for content access. Keep targets within the trusted
	// workspace mount. A dangling link is enrolled, but has no existing target.
	byPath := make(map[string]filesystemPolicyEntry)
	for len(entries) != 0 {
		entry := entries[0]
		entries = entries[1:]
		if previous, ok := byPath[entry.Path]; ok && previous.Mode >= entry.Mode {
			continue
		}
		full := filepath.Join(workspace, entry.Path)
		info, err := os.Lstat(full)
		if err != nil {
			return nil, fmt.Errorf("snapshot %q: %w", entry.Path, err)
		}
		entry.NoFollow = info.Mode()&os.ModeSymlink != 0
		byPath[entry.Path] = entry
		if !entry.NoFollow {
			continue
		}
		target, err := filepath.EvalSymlinks(full)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("resolve protected symlink %q: %w", entry.Path, err)
		}
		rel, err := filepath.Rel(workspace, target)
		if err != nil || !filepath.IsLocal(rel) || rel == "." {
			return nil, fmt.Errorf("protected symlink %q must resolve within the workspace below its root", entry.Path)
		}
		err = filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(workspace, path)
			if err != nil {
				return err
			}
			entries = append(entries, filesystemPolicyEntry{Path: rel, Mode: entry.Mode})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("enumerate protected symlink target: %w", err)
		}
	}
	for _, entry := range byPath {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}
