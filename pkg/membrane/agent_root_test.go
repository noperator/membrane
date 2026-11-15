package membrane

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Templates can import external credentials by symlink. Both source updates and
// session writes must stay isolated, including repeated references to one file.
func TestPrepareAgentRootIndependence(t *testing.T) {
	root := t.TempDir()
	source, external := filepath.Join(root, "source"), filepath.Join(root, "external")
	for _, dir := range []string{source, external, filepath.Join(source, "empty"), filepath.Join(source, "home/agent/bin")} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(external, "settings"), []byte("original"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "home/agent/bin/tool"), []byte("#!/bin/sh\nexit 0\n"), 0751); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"first": external, "second": "../external", "nested": "first/settings",
	} {
		if err := os.Symlink(target, filepath.Join(source, name)); err != nil {
			t.Fatal(err)
		}
	}
	stage := filepath.Join(root, "session")
	if err := prepareAgentRoot(context.Background(), source, stage); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{
		"empty": os.ModeDir | 0755, "first": os.ModeDir | 0755,
		"first/settings": 0640, "second/settings": 0640, "nested": 0640,
		"home/agent/bin/tool": 0751,
	} {
		info, err := os.Lstat(filepath.Join(stage, name))
		if err != nil || info.Mode() != mode {
			t.Fatalf("staged %s: info=%v err=%v; want %v", name, info, err, mode)
		}
	}
	if err := os.WriteFile(filepath.Join(stage, "first/settings"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(external, "settings"), filepath.Join(stage, "second/settings"), filepath.Join(stage, "nested")} {
		if data, err := os.ReadFile(name); err != nil || string(data) != "original" {
			t.Fatalf("copy mutation reached %s: %q (%v)", name, data, err)
		}
	}
	if err := os.WriteFile(filepath.Join(external, "settings"), []byte("next session"), 0640); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(stage, "nested")); err != nil || string(data) != "original" {
		t.Fatalf("source update affected prepared session: %q (%v)", data, err)
	}
	next := filepath.Join(root, "later-session")
	if err := prepareAgentRoot(context.Background(), source, next); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(next, "nested")); err != nil || string(data) != "next session" {
		t.Fatalf("later session missed source update: %q (%v)", data, err)
	}
	empty := filepath.Join(root, "empty")
	if err := os.Mkdir(empty, 0755); err != nil {
		t.Fatal(err)
	}
	if err := prepareAgentRoot(context.Background(), empty, filepath.Join(root, "empty-session")); err != nil {
		t.Fatalf("empty template: %v", err)
	}
}

// Bad links and special files must fail promptly with their source path rather
// than hanging launch, recursively copying forever, or changing the original.
func TestPrepareAgentRootRejectsUnusableSources(t *testing.T) {
	for _, kind := range []string{"broken", "link-cycle", "directory-cycle", "fifo", "socket", "device", "staging-parent"} {
		t.Run(kind, func(t *testing.T) {
			// Keep Unix socket paths below macOS's sockaddr_un limit.
			root, err := os.MkdirTemp("", "agent-root-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(root) })
			source := filepath.Join(root, "source")
			if err := os.Mkdir(source, 0700); err != nil {
				t.Fatal(err)
			}
			bad := filepath.Join(source, "bad")
			stage := filepath.Join(root, "session")
			switch kind {
			case "broken":
				err = os.Symlink("absent", bad)
			case "link-cycle":
				err = os.Symlink("bad", bad)
			case "directory-cycle":
				err = os.Symlink(".", bad)
			case "staging-parent":
				err = os.Mkdir(filepath.Join(root, "runtime"), 0700)
				if err == nil {
					err = os.Symlink("../runtime", bad)
				}
				stage = filepath.Join(root, "runtime", "session")
			case "fifo":
				err = syscall.Mkfifo(bad, 0600)
			case "device":
				err = os.Symlink("/dev/null", bad)
			case "socket":
				var listener net.Listener
				listener, err = net.Listen("unix", bad)
				if err == nil {
					defer listener.Close()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			err = prepareAgentRoot(context.Background(), source, stage)
			if err == nil || !strings.Contains(err.Error(), bad) {
				t.Fatalf("expected path-specific rejection for %s: %v", kind, err)
			}
			if _, err := os.Lstat(bad); err != nil {
				t.Fatalf("rejected template entry was changed: %v", err)
			}
			if _, err := os.Lstat(stage); !os.IsNotExist(err) {
				t.Fatalf("failed preparation left a partial tree: %v", err)
			}
		})
	}
}

// Preserving readonly modes must not strand a session's disposable tree or make
// cleanup chmod a host source through a link.
func TestPreparedAgentRootReadonlyCleanup(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "file"), []byte("readonly"), 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(source, 0755); err != nil {
			t.Errorf("restore source permissions: %v", err)
		}
	})
	stage := filepath.Join(root, "stage")
	if err := prepareAgentRoot(context.Background(), source, stage); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(stage); err != nil || info.Mode().Perm() != 0555 {
		t.Fatalf("readonly directory mode lost: %v (%v)", info, err)
	}
	if err := removePreparedAgentRoot(stage); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("staged readonly tree retained: %v", err)
	}
	if err := os.Symlink(source, stage); err != nil {
		t.Fatal(err)
	}
	if err := removePreparedAgentRoot(stage); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(source); err != nil || info.Mode().Perm() != 0555 {
		t.Fatalf("cleanup modified host source: %v (%v)", info, err)
	}
}

// Setup must never truncate customized instructions or write through directory
// references into another host tree when initializing the two default copies.
func TestAgentRootDefaults(t *testing.T) {
	for _, kind := range []string{"missing", "custom", "file-link", "directory-link", "broken-link"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "src"), 0755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"config.yaml", "AGENTS.md"} {
				if err := os.WriteFile(filepath.Join(root, "src", name), []byte("shipped"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			parent := filepath.Join(root, "agent-root/etc/membrane")
			if err := os.MkdirAll(parent, 0755); err != nil {
				t.Fatal(err)
			}
			dest := filepath.Join(parent, "AGENTS.md")
			var err error
			switch kind {
			case "custom":
				err = os.WriteFile(dest, []byte("custom"), 0600)
			case "file-link", "broken-link":
				err = os.Symlink("../../../instructions", dest)
				if err == nil && kind == "file-link" {
					err = os.WriteFile(filepath.Join(root, "instructions"), []byte("custom"), 0600)
				}
			case "directory-link":
				err = os.Remove(parent)
				if err == nil {
					err = os.Mkdir(filepath.Join(root, "external"), 0755)
				}
				if err == nil {
					err = os.Symlink(filepath.Join(root, "external"), parent)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if err := writeDefaultFiles(root); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "directory-link" {
				entries, err := os.ReadDir(filepath.Join(root, "external"))
				if err != nil || len(entries) != 0 {
					t.Fatalf("setup wrote through directory link: %v (%v)", entries, err)
				}
			} else if kind == "broken-link" {
				if _, err := os.Readlink(dest); err != nil {
					t.Fatalf("setup replaced broken link: %v", err)
				}
			} else {
				want := "custom"
				if kind == "missing" {
					want = "shipped"
				}
				if data, err := os.ReadFile(dest); err != nil || string(data) != want {
					t.Fatalf("default overwrote user input: %q (%v)", data, err)
				}
			}
			claude := filepath.Join(root, "agent-root/etc/claude-code/CLAUDE.md")
			if data, err := os.ReadFile(claude); err != nil || string(data) != "shipped" {
				t.Fatalf("Claude default: %q (%v)", data, err)
			}
			if info, err := os.Lstat(claude); err != nil || !info.Mode().IsRegular() {
				t.Fatalf("default is not an independent regular file: %v (%v)", info, err)
			}
		})
	}
}
