package membrane

import (
	"path/filepath"
	"strings"
)

// Anchors are classified before cleaning. Unanchored patterns match suffixes
// at component boundaries in relative, which starts at a selected tree's root.
func matchesAny(workspace, path, relative string, patterns []string) bool {
	for _, pattern := range patterns {
		absolute := filepath.IsAbs(pattern)
		anchored := absolute || strings.HasPrefix(pattern, "./") || strings.HasPrefix(pattern, "../")
		if trimmed := strings.TrimRight(pattern, "/"); trimmed != "" {
			pattern = trimmed
		}
		if anchored {
			candidate := path
			if !absolute {
				// Normalize against the workspace, then compare relative paths
				// so literal glob characters in its host path stay literal.
				pattern, _ = filepath.Rel(workspace, filepath.Join(workspace, pattern))
				var err error
				candidate, err = filepath.Rel(workspace, path)
				if err != nil {
					continue
				}
			}
			if matched, _ := filepath.Match(filepath.Clean(pattern), candidate); matched {
				return true
			}
			continue
		}
		for candidate := relative; ; {
			if matched, _ := filepath.Match(pattern, candidate); matched {
				return true
			}
			separator := strings.IndexByte(candidate, filepath.Separator)
			if separator < 0 {
				break
			}
			candidate = candidate[separator+1:]
		}
	}
	return false
}
