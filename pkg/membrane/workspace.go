package membrane

import (
	"path/filepath"
	"strings"
)

// matchesAny checks if a path matches any of the given patterns.
// Path-based patterns (containing /) match against the full relative path.
// Name-based patterns match against just the filename.
func matchesAny(relPath, name string, patterns []string) bool {
	for _, pattern := range patterns {
		trimmed := strings.TrimRight(pattern, "/")
		if strings.Contains(trimmed, "/") {
			if matched, _ := filepath.Match(trimmed, relPath); matched {
				return true
			}
		} else {
			if matched, _ := filepath.Match(trimmed, name); matched {
				return true
			}
		}
	}
	return false
}
