package membrane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveMounts(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loop", filepath.Join(root, "loop")); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ path, mode, message string }{
		{"missing", "rw", "no such file"}, {"file", "ro", "not a directory"},
		{"loop", "rw", "too many links"}, {".", "ro", "conflicting modes"},
	} {
		_, err := resolveMounts(root, []directoryMount{{Path: test.path, Mode: test.mode}})
		if err == nil || !strings.Contains(err.Error(), test.message) || !strings.Contains(err.Error(), "mounts[0]") {
			t.Fatalf("%s: expected %q: %v", test.path, test.message, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "missing")); !os.IsNotExist(err) {
		t.Fatalf("source directory created: %v", err)
	}
	additional := filepath.Join(root, "directory with spaces")
	if err := os.Mkdir(additional, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(additional, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	configured := []directoryMount{{Path: ".", Mode: "rw"}, {Path: "alias", Mode: "ro"}, {Path: additional, Mode: "ro"}}
	mounts, err := resolveMounts(root, configured)
	if err != nil || len(mounts) != 2 || mounts[0] != (directoryMount{root, "rw"}) || mounts[1] != (directoryMount{additional, "ro"}) {
		t.Fatalf("canonical mounts and duplicate collapse: %v, %v", mounts, err)
	}
	configured[2].Mode = "rw"
	if _, err := resolveMounts(root, configured); err == nil || !strings.Contains(err.Error(), "conflicting modes") {
		t.Fatalf("canonical alias conflict: %v", err)
	}
	if os.Geteuid() != 0 {
		path := filepath.Join(root, "unreadable")
		if err := os.Mkdir(path, 0000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(path, 0700)
		if _, err := resolveMounts(root, []directoryMount{{Path: path, Mode: "rw"}}); err == nil {
			t.Fatal("unreadable mount accepted")
		}
	}
}
