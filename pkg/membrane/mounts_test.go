package membrane

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func resolveMountsWithWarnings(t *testing.T, workspace string, configured []directoryMount) ([]directoryMount, string, error) {
	t.Helper()
	output, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	stderr := os.Stderr
	os.Stderr = output
	defer func() { os.Stderr = stderr }()
	mounts, resolveErr := resolveMounts(workspace, configured)
	warnings, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	return mounts, string(warnings), resolveErr
}

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
		{"loop", "rw", "too many links"},
	} {
		_, err := resolveMounts(root, []directoryMount{{Path: test.path, Mode: test.mode}})
		if err == nil || !strings.Contains(err.Error(), test.message) || !strings.Contains(err.Error(), "mounts[0]") {
			t.Fatalf("%s: expected %q: %v", test.path, test.message, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "missing")); !os.IsNotExist(err) {
		t.Fatalf("source directory created: %v", err)
	}
	additional := filepath.Join(root, "directory with spaces\nand controls\t\x1b")
	later := filepath.Join(root, "later")
	for _, path := range []string{additional, later} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(additional, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	// Aliases must not loosen restrictions or produce duplicate binds. Repeated
	// conflicts warn once per path, with control characters escaped for terminals.
	for _, test := range []struct {
		name       string
		configured []directoryMount
		want       []directoryMount
		conflicts  []string
	}{
		{"workspace agreement", []directoryMount{{Path: ".", Mode: "rw"}},
			[]directoryMount{{Path: root, Mode: "rw"}}, nil},
		{"workspace conflict", []directoryMount{{Path: ".", Mode: "ro"}, {Path: root, Mode: "rw"}, {Path: ".", Mode: "ro"}},
			[]directoryMount{{Path: root, Mode: "ro"}}, []string{root}},
		{"readonly agreement", []directoryMount{{Path: "alias", Mode: "ro"}, {Path: additional, Mode: "ro"}},
			[]directoryMount{{Path: root, Mode: "rw"}, {Path: additional, Mode: "ro"}}, nil},
		{"writable agreement", []directoryMount{{Path: "alias", Mode: "rw"}, {Path: additional, Mode: "rw"}},
			[]directoryMount{{Path: root, Mode: "rw"}, {Path: additional, Mode: "rw"}}, nil},
		{"readonly first", []directoryMount{{Path: "alias", Mode: "ro"}, {Path: additional, Mode: "rw"}, {Path: additional, Mode: "rw"}},
			[]directoryMount{{Path: root, Mode: "rw"}, {Path: additional, Mode: "ro"}}, []string{additional}},
		{"writable first", []directoryMount{{Path: additional, Mode: "rw"}, {Path: "alias", Mode: "ro"}, {Path: additional, Mode: "rw"}},
			[]directoryMount{{Path: root, Mode: "rw"}, {Path: additional, Mode: "ro"}}, []string{additional}},
		{"two conflicts preserve order", []directoryMount{{Path: "alias", Mode: "rw"}, {Path: later, Mode: "rw"}, {Path: ".", Mode: "ro"}, {Path: additional, Mode: "ro"}, {Path: ".", Mode: "rw"}, {Path: "alias", Mode: "rw"}},
			[]directoryMount{{Path: root, Mode: "ro"}, {Path: additional, Mode: "ro"}, {Path: later, Mode: "rw"}}, []string{root, additional}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mounts, warnings, err := resolveMountsWithWarnings(t, root, test.configured)
			if err != nil || !reflect.DeepEqual(mounts, test.want) {
				t.Fatalf("mounts = %v, %v; want %v", mounts, err, test.want)
			}
			if strings.Count(warnings, "\n") != len(test.conflicts) || strings.Count(warnings, "membrane: warning:") != len(test.conflicts) || strings.ContainsAny(warnings, "\t\x1b") {
				t.Fatalf("expected one physical line per conflicting path: %q", warnings)
			}
			for _, path := range test.conflicts {
				prefix := fmt.Sprintf("membrane: warning: conflicting mount modes for %q", path)
				if strings.Count(warnings, prefix) != 1 {
					t.Fatalf("missing canonical path in warning: %q", warnings)
				}
			}
			for _, line := range strings.Split(strings.TrimSuffix(warnings, "\n"), "\n") {
				if line != "" && (!strings.Contains(line, "mounts[") || !strings.Contains(line, ": rw") || !strings.Contains(line, ": ro") || !strings.HasSuffix(line, "using ro")) {
					t.Fatalf("warning must identify requests and selected mode: %q", line)
				}
			}
		})
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
			mounts, warnings, err := resolveMountsWithWarnings(t, test.workspace, []directoryMount{{Type: "git-root", Mode: mode}})
			want := []directoryMount{{Path: test.workspace, Mode: "rw"}}
			if test.workspace != test.main {
				want = append(want, directoryMount{Path: test.main, Mode: mode})
			} else {
				want[0].Mode = mode
			}
			if err != nil || !reflect.DeepEqual(mounts, want) {
				t.Fatalf("workspace %q mode %s: %v, %v; want %v", test.workspace, mode, mounts, err, want)
			}
			// Main and bare workspaces must honor discovery just like explicit
			// equal-path mounts; distinct parent/child paths remain silent.
			if test.workspace == test.main && mode == "ro" {
				if strings.Count(warnings, "\n") != 1 || !strings.Contains(warnings, fmt.Sprintf("%q", test.main)) {
					t.Fatalf("expected one warning with the escaped canonical path: %q", warnings)
				}
			} else if warnings != "" {
				t.Fatalf("workspace %q mode %s: unexpected warning: %q", test.workspace, mode, warnings)
			}
		}
	}
	alias := filepath.Join(root, "repo alias")
	if err := os.Symlink(repo, alias); err != nil {
		t.Fatal(err)
	}
	want := []directoryMount{{Path: linked, Mode: "rw"}, {Path: repo, Mode: "ro"}}
	// Discovery and explicit aliases must not create competing binds or let
	// declaration order loosen a readonly request.
	for _, mode := range []string{"ro", "rw"} {
		for _, reverse := range []bool{false, true} {
			configured := []directoryMount{{Type: "git-root", Mode: mode}, {Path: alias, Mode: "ro"}}
			if reverse {
				configured[0], configured[1] = configured[1], configured[0]
			}
			mounts, warnings, err := resolveMountsWithWarnings(t, linked, configured)
			if err != nil || !reflect.DeepEqual(mounts, want) || (warnings != "") != (mode == "rw") {
				t.Fatalf("canonical explicit/typed duplicates, mode=%s reverse=%v: %v, %v, %q", mode, reverse, mounts, err, warnings)
			}
		}
	}
	configured := []directoryMount{{Type: "git-root", Mode: "rw"}}
	if _, err := resolveMounts(root, configured); err == nil || !strings.Contains(err.Error(), `mounts[0] type "git-root"`) {
		t.Fatalf("non-repository must fail discovery: %v", err)
	}
	gitDir := t.TempDir()
	t.Setenv("PATH", gitDir)
	if _, err := resolveMounts(linked, []directoryMount{{Path: repo, Mode: "ro"}}); err != nil {
		t.Fatalf("explicit mounts must not require Git: %v", err)
	}
	if _, err := resolveMounts(linked, configured); err == nil || !strings.Contains(err.Error(), `mounts[0] type "git-root"`) {
		t.Fatalf("missing Git must fail discovery: %v", err)
	}
	// Even a successful command must supply usable porcelain output.
	if err := os.WriteFile(filepath.Join(gitDir, "git"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveMounts(linked, configured); err == nil || !strings.Contains(err.Error(), "no usable repository path") {
		t.Fatalf("empty Git output must fail discovery: %v", err)
	}
}
