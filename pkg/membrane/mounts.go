package membrane

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The primary workspace is always first, with an implicit rw request.
func resolveMounts(workspace string, configured []directoryMount) ([]directoryMount, error) {
	mounts := []directoryMount{{Path: workspace, Mode: "rw"}}
	type mountSource struct {
		index  int
		label  string
		warned bool
	}
	seen := map[string]mountSource{workspace: {label: "primary workspace"}}
	for i, mount := range configured {
		path := mount.Path
		source := fmt.Sprintf("mounts[%d] path %q", i, path)
		if mount.Type != "" {
			source = fmt.Sprintf("mounts[%d] type %q", i, mount.Type)
			args := []string{"worktree", "list", "--porcelain", "-z"}
			command := "git worktree list"
			if mount.Type == "git-meta" {
				args = []string{"rev-parse", "--path-format=absolute", "--git-common-dir"}
				command = "git rev-parse --git-common-dir"
			}
			cmd := exec.Command("git", append([]string{"-C", workspace}, args...)...)
			var stderr strings.Builder
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %w: %s", source, command, err, strings.TrimSpace(stderr.String()))
			}
			if mount.Type == "git-meta" {
				// Only the final newline belongs to Git; whitespace before it
				// can be part of the common directory's name.
				path = strings.TrimSuffix(string(out), "\n")
			} else {
				// Git lists the main worktree (or bare repository) first, with
				// worktree as its first attribute. NULs preserve spaces/newlines.
				record, _, complete := strings.Cut(string(out), "\x00\x00")
				attribute, _, _ := strings.Cut(record, "\x00")
				var valid bool
				path, valid = strings.CutPrefix(attribute, "worktree ")
				if !complete || !valid {
					path = ""
				}
			}
			if !filepath.IsAbs(path) {
				return nil, fmt.Errorf("%s: %s returned no usable repository path", source, command)
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
		// Merge in place to preserve the workspace position and policy root indexes.
		if previous, ok := seen[path]; ok {
			if mounts[previous.index].Mode != mount.Mode {
				if !previous.warned {
					fmt.Fprintf(os.Stderr, "membrane: warning: conflicting mount modes for %q (%s: %s; %s: %s); using ro\n",
						path, previous.label, mounts[previous.index].Mode, source, mount.Mode)
					previous.warned = true
					seen[path] = previous
				}
				mounts[previous.index].Mode = "ro"
			}
			continue
		}
		seen[path] = mountSource{index: len(mounts), label: source}
		mounts = append(mounts, directoryMount{Path: path, Mode: mount.Mode})
	}
	return mounts, nil
}
