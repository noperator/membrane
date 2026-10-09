package membrane

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
	if err != nil || len(mounts) != 2 || mounts[0] != (directoryMount{Path: root, Mode: "rw"}) || mounts[1] != (directoryMount{Path: additional, Mode: "ro"}) {
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
		t.Cleanup(func() {
			if err := os.Chmod(path, 0700); err != nil {
				t.Errorf("restore mount fixture permissions: %v", err)
			}
		})
		if _, err := resolveMounts(root, []directoryMount{{Path: path, Mode: "rw"}}); err == nil {
			t.Fatal("unreadable mount accepted")
		}
	}
}

func TestResolveGitRootMounts(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		args = append([]string{"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false"}, args...)
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %q: %v\n%s", args, err, out)
		}
	}
	repo := filepath.Join(root, "main repo\nwith newline")
	linked := filepath.Join(root, "linked worktree")
	bare := filepath.Join(root, "bare repo.git")
	bareLinked := filepath.Join(root, "bare linked worktree")
	git("init", repo)
	git("-C", repo, "-c", "user.name=Membrane Test", "-c", "user.email=membrane@example.invalid",
		"commit", "--allow-empty", "-m", "fixture")
	git("-C", repo, "worktree", "add", "--detach", linked)
	git("clone", "--bare", repo, bare)
	git("-C", bare, "worktree", "add", "--detach", bareLinked)
	for _, workspace := range []string{repo, linked} {
		if err := os.Mkdir(filepath.Join(workspace, "subdir"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct{ workspace, main string }{
		{repo, repo}, {filepath.Join(repo, "subdir"), repo},
		{linked, repo}, {filepath.Join(linked, "subdir"), repo},
		{bare, bare}, {bareLinked, bare},
	} {
		for _, mode := range []string{"rw", "ro"} {
			mounts, err := resolveMounts(test.workspace, []directoryMount{{Type: "git-root", Mode: mode}})
			if test.workspace == test.main && mode == "ro" {
				if err == nil || !strings.Contains(err.Error(), `mounts[0] type "git-root"`) || !strings.Contains(err.Error(), "conflicting modes") {
					t.Fatalf("same-root readonly conflict: %v", err)
				}
				continue
			}
			want := []directoryMount{{Path: test.workspace, Mode: "rw"}}
			if test.workspace != test.main {
				want = append(want, directoryMount{Path: test.main, Mode: mode})
			}
			if err != nil || !reflect.DeepEqual(mounts, want) {
				t.Fatalf("workspace %q mode %s: %v, %v; want %v", test.workspace, mode, mounts, err, want)
			}
		}
	}
	alias := filepath.Join(root, "repo alias")
	if err := os.Symlink(repo, alias); err != nil {
		t.Fatal(err)
	}
	configured := []directoryMount{{Type: "git-root", Mode: "ro"}, {Path: alias, Mode: "ro"}}
	want := []directoryMount{{Path: linked, Mode: "rw"}, {Path: repo, Mode: "ro"}}
	if mounts, err := resolveMounts(linked, configured); err != nil || !reflect.DeepEqual(mounts, want) {
		t.Fatalf("canonical explicit/typed duplicates: %v, %v", mounts, err)
	}
	configured[0].Mode = "rw"
	if _, err := resolveMounts(linked, configured); err == nil || !strings.Contains(err.Error(), "conflicting modes") {
		t.Fatalf("explicit/typed conflict: %v", err)
	}
	if _, err := resolveMounts(root, configured[:1]); err == nil || !strings.Contains(err.Error(), `mounts[0] type "git-root"`) {
		t.Fatalf("non-repository must fail discovery: %v", err)
	}
	gitDir := t.TempDir()
	t.Setenv("PATH", gitDir)
	if _, err := resolveMounts(linked, []directoryMount{{Path: repo, Mode: "ro"}}); err != nil {
		t.Fatalf("explicit mounts must not require Git: %v", err)
	}
	if _, err := resolveMounts(linked, configured[:1]); err == nil || !strings.Contains(err.Error(), `mounts[0] type "git-root"`) {
		t.Fatalf("missing Git must fail discovery: %v", err)
	}
	// Even a successful command must supply usable porcelain output.
	if err := os.WriteFile(filepath.Join(gitDir, "git"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveMounts(linked, configured[:1]); err == nil || !strings.Contains(err.Error(), "no usable repository path") {
		t.Fatalf("empty Git output must fail discovery: %v", err)
	}
}
