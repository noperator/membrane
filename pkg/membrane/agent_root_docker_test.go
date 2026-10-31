package membrane

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real Engine archive operations can materialize mounts before docker start.
// This regression must prove safe copy-in on an actual container filesystem,
// including symlinked mount destinations, rather than mocking Docker's view.
// Opt in with MEMBRANE_TEST_DOCKER=1; no pulls, builds or workload code are used.
func TestCopyAgentRootDocker(t *testing.T) {
	if os.Getenv("MEMBRANE_TEST_DOCKER") != "1" {
		t.Skip("set MEMBRANE_TEST_DOCKER=1 to test disposable Docker containers")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	docker := func(input io.Reader, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, "docker", args...)
		cmd.Stdin = input
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("docker %v: %s (%v)", args, out, err)
		}
		return out
	}
	var image bytes.Buffer
	tw := tar.NewWriter(&image)
	for _, name := range []string{"etc", "dev", "home", "home/agent", "existing", "dir", "target", "host-real", "redirected"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"existing/keep", "existing/replaced", "file", "dir/keep", "target/marker", "home/agent/image-file"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0644, Size: 5}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("image")); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"link": "/target", "leaf-link": "/target/marker", "host-alias": "/host-real"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeSymlink, Mode: 0777, Linkname: target}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	imageID := strings.TrimSpace(string(docker(&image, "import", "-")))
	t.Cleanup(func() {
		if out, err := exec.Command("docker", "image", "rm", imageID).CombinedOutput(); err != nil {
			t.Errorf("remove fixture image: %s (%v)", out, err)
		}
	})
	create := func(args ...string) string {
		t.Helper()
		args = append([]string{"create", "--network=none"}, args...)
		args = append(args, imageID, "/must-never-run")
		id := strings.TrimSpace(string(docker(nil, args...)))
		t.Cleanup(func() {
			if out, err := exec.Command("docker", "rm", "-f", id).CombinedOutput(); err != nil {
				t.Errorf("remove fixture container: %s (%v)", out, err)
			}
		})
		return id
	}
	read := func(id, name string) (map[string]string, map[string]tar.Header) {
		t.Helper()
		tr := tar.NewReader(bytes.NewReader(docker(nil, "cp", id+":"+name, "-")))
		contents, headers := make(map[string]string), make(map[string]tar.Header)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			contents[h.Name], headers[h.Name] = string(data), *h
		}
		return contents, headers
	}
	write := func(root, name, content string, mode os.FileMode) {
		t.Helper()
		name = filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("overlay-and-mount-exclusions", func(t *testing.T) {
		// Colima shares the workspace but need not share macOS's t.TempDir.
		fixture, err := os.MkdirTemp(".", ".agent-root-test-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(fixture) })
		fixture, err = filepath.Abs(fixture)
		if err != nil {
			t.Fatal(err)
		}
		write(fixture, "host/marker", "host", 0640)
		write(fixture, "host-file", "host file", 0600)
		write(fixture, "nested-host/marker", "nested host", 0640)
		if err := os.Symlink("/redirected", filepath.Join(fixture, "host/nested-link")); err != nil {
			t.Fatal(err)
		}
		stage := filepath.Join(fixture, "stage")
		for name, content := range map[string]string{
			"existing/replaced": "template", "existing/added": "new",
			"home/agent/tool": "private tool", "home/agent/project/marker": "must not copy",
			"host-real/marker": "must not copy", "file-mount": "must not copy",
			"redirected/marker": "must not copy",
			"etc/hosts":         "must not copy", "proc/must-not-copy": "must not copy",
		} {
			write(stage, name, content, 0700)
		}
		if err := os.Mkdir(filepath.Join(stage, "private-empty"), 0750); err != nil {
			t.Fatal(err)
		}
		id := create("--mount", directoryBind(filepath.Join(fixture, "host"), "/home/agent/project", false),
			"--mount", directoryBind(filepath.Join(fixture, "host"), "/host-alias", false),
			"--mount", directoryBind(filepath.Join(fixture, "nested-host"), "/home/agent/project/nested-link", false),
			"--mount", directoryBind(filepath.Join(fixture, "host-file"), "/file-mount", true))
		if err := copyAgentRoot(ctx, stage, id, 1234, 2345); err != nil {
			t.Fatal(err)
		}
		contents, headers := read(id, "/existing")
		if contents["existing/keep"] != "image" || contents["existing/replaced"] != "template" || contents["existing/added"] != "new" || headers["existing/added"].Mode != 0700 {
			t.Fatalf("overlay lost image contents or modes: %v %v", contents, headers)
		}
		contents, headers = read(id, "/home/agent/tool")
		if contents["tool"] != "private tool" || headers["tool"].Uid != 1234 || headers["tool"].Gid != 2345 {
			t.Fatalf("private home ownership: %v %v", contents, headers)
		}
		_, headers = read(id, "/private-empty")
		if headers["private-empty/"].Typeflag != tar.TypeDir || headers["private-empty/"].Mode != 0750 {
			t.Fatalf("empty directory lost: %v", headers)
		}
		for name, want := range map[string]string{"host/marker": "host", "host-file": "host file", "nested-host/marker": "nested host"} {
			if data, err := os.ReadFile(filepath.Join(fixture, name)); err != nil || string(data) != want {
				t.Fatalf("template wrote through %s: %q (%v)", name, data, err)
			}
		}
		if state := strings.TrimSpace(string(docker(nil, "inspect", "-f", "{{.State.Status}}", id))); state != "created" {
			t.Fatalf("workload executed during preparation: %s", state)
		}
		if files, _ := filepath.Glob(filepath.Join(fixture, "agent-root-*.tar")); len(files) != 0 {
			t.Fatalf("transfer files retained: %v", files)
		}
	})

	for _, name := range []string{"link/escape", "leaf-link", "file/child", "dir", "usr/local/bin/entrypoint.sh"} {
		t.Run("reject-"+name, func(t *testing.T) {
			stage := filepath.Join(t.TempDir(), "stage")
			write(stage, "existing/replaced", "must not be sent", 0644)
			write(stage, name, "must not be sent", 0644)
			id := create()
			err := copyAgentRoot(ctx, stage, id, 1000, 1000)
			if err == nil || !strings.Contains(err.Error(), "/"+strings.Split(name, "/")[0]) {
				t.Fatalf("expected path-specific collision failure for %s: %v", name, err)
			}
			contents, _ := read(id, "/existing/replaced")
			if contents["replaced"] != "image" {
				t.Fatalf("failed preflight partially copied template: %v", contents)
			}
			contents, _ = read(id, "/target/marker")
			if contents["marker"] != "image" {
				t.Fatalf("copy followed destination link: %v", contents)
			}
		})
	}
}
