package membrane

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The primary workspace is always the first, implicit writable mount.
func resolveMounts(workspace string, configured []directoryMount) ([]directoryMount, error) {
	mounts := []directoryMount{{Path: workspace, Mode: "rw"}}
	seen := map[string]string{workspace: "rw"}
	for i, mount := range configured {
		path := mount.Path
		source := fmt.Sprintf("mounts[%d] path %q", i, path)
		if mount.Type == "git-root" {
			source = fmt.Sprintf("mounts[%d] type %q", i, mount.Type)
			cmd := exec.Command("git", "-C", workspace, "worktree", "list", "--porcelain", "-z")
			var stderr strings.Builder
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				return nil, fmt.Errorf("%s: git worktree list: %w: %s", source, err, strings.TrimSpace(stderr.String()))
			}
			// Git lists the main worktree (or bare repository) first, with
			// worktree as its first attribute. NULs preserve spaces/newlines.
			record, _, complete := strings.Cut(string(out), "\x00\x00")
			attribute, _, _ := strings.Cut(record, "\x00")
			var valid bool
			path, valid = strings.CutPrefix(attribute, "worktree ")
			if !complete || !valid || !filepath.IsAbs(path) {
				return nil, fmt.Errorf("%s: git worktree list returned no usable repository path", source)
			}
			source += fmt.Sprintf(" path %q", path)
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(workspace, path)
		}
		path, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%s: not a directory", source)
		}
		// Opening and enumerating also validates writable mounts before Docker
		// can start the workload. Never create a missing source directory.
		if _, err := os.ReadDir(path); err != nil {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		if previous, ok := seen[path]; ok {
			if previous != mount.Mode {
				return nil, fmt.Errorf("%s: conflicting modes %s and %s for %q", source, previous, mount.Mode, path)
			}
			continue
		}
		seen[path] = mount.Mode
		mounts = append(mounts, directoryMount{Path: path, Mode: mount.Mode})
	}
	return mounts, nil
}
