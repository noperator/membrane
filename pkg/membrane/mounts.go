package membrane

import (
	"fmt"
	"os"
	"path/filepath"
)

// The primary workspace is always the first, implicit writable mount.
func resolveMounts(workspace string, configured []directoryMount) ([]directoryMount, error) {
	mounts := []directoryMount{{Path: workspace, Mode: "rw"}}
	seen := map[string]string{workspace: "rw"}
	for i, mount := range configured {
		path := mount.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(workspace, path)
		}
		path, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, fmt.Errorf("mounts[%d] path %q: %w", i, mount.Path, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("mounts[%d] path %q: %w", i, mount.Path, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("mounts[%d] path %q: not a directory", i, mount.Path)
		}
		// Opening and enumerating also validates writable mounts before Docker
		// can start the workload. Never create a missing source directory.
		if _, err := os.ReadDir(path); err != nil {
			return nil, fmt.Errorf("mounts[%d] path %q: %w", i, mount.Path, err)
		}
		if previous, ok := seen[path]; ok {
			if previous != mount.Mode {
				return nil, fmt.Errorf("mounts[%d] path %q: conflicting modes %s and %s for %q", i, mount.Path, previous, mount.Mode, path)
			}
			continue
		}
		seen[path] = mount.Mode
		mounts = append(mounts, directoryMount{Path: path, Mode: mount.Mode})
	}
	return mounts, nil
}
