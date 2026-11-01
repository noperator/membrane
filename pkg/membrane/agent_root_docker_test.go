package membrane

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
// Opt in with MEMBRANE_TEST_DOCKER=1; no pulls or image builds are used. A tiny
// static exit program lets the archive case inspect a genuinely exited source.
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
	program := t.TempDir()
	if err := os.WriteFile(filepath.Join(program, "main.go"), []byte(`package main
import "os"
func main() { if err := os.WriteFile("/executed", []byte("ran"), 0600); err != nil { panic(err) } }
`), 0600); err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", filepath.Join(program, "exit"), filepath.Join(program, "main.go"))
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+strings.TrimSpace(string(docker(nil, "version", "--format", "{{.Server.Arch}}"))))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build disposable exit program: %s (%v)", out, err)
	}
	executable, err := os.ReadFile(filepath.Join(program, "exit"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "exit", Typeflag: tar.TypeReg, Mode: 0755, Size: int64(len(executable))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(executable); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"etc", "dev", "home", "home/agent", "existing", "dir", "target", "host-real", "redirected", "usr", "usr/local", "usr/local/share", "usr/local/share/membrane", "usr/lib", "usr/lib/startup-runtime"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
			t.Fatal(err)
		}
	}
	reserved := "/usr/local/share/membrane/startup-paths\n/usr/local/bin/entrypoint.sh\n/etc/passwd\n/etc/group\n/usr/lib/startup-runtime\n"
	if err := tw.WriteHeader(&tar.Header{Name: "usr/local/share/membrane/startup-paths", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(reserved))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(reserved)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"existing/keep", "existing/replaced", "file", "dir/keep", "target/marker", "home/agent/image-file"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0644, Size: 5}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("image")); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"home/agent/project", "home/agent/project/child"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string]string{
		"home/agent/project/hidden": "hidden directory bytes", "home/agent/file-mount": "hidden file bytes",
		"a-private-source": "hardlink bytes", "etc/chosen": "selected elsewhere",
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0640, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	for _, header := range []tar.Header{
		{Name: "home/agent/hardlink", Typeflag: tar.TypeLink, Linkname: "a-private-source", Mode: 0640},
		{Name: "home/agent/host-link", Typeflag: tar.TypeSymlink, Linkname: "/home/agent/project/host-only", Mode: 0777},
		{Name: "home/agent/pipe", Typeflag: tar.TypeFifo, Mode: 0600},
	} {
		if err := tw.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"link": "/target", "leaf-link": "/target/marker", "host-alias": "/host-real", "startup-alias": "/usr/lib/startup-runtime"} {
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
		args = append(args, imageID, "/exit")
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
		if _, err := copyAgentRoot(ctx, stage, id, 1234, 2345); err != nil {
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

	// A configured mount must not hide the trusted startup list or redirect
	// setup into replacement libraries through an image-side alias.
	for _, destination := range []string{"/usr/local/share/membrane", "/usr/lib/startup-runtime", "/startup-alias"} {
		t.Run("reserved-mount-"+destination, func(t *testing.T) {
			stage := t.TempDir()
			write(stage, "existing/replaced", "must not be sent", 0644)
			id := create("--tmpfs", destination)
			_, err := copyAgentRoot(ctx, stage, id, 1000, 1000)
			if err == nil || !strings.Contains(err.Error(), destination) {
				t.Fatalf("expected reserved mount rejection for %s: %v", destination, err)
			}
			contents, _ := read(id, "/existing/replaced")
			if contents["replaced"] != "image" {
				t.Fatalf("failed mount preflight copied template: %v", contents)
			}
		})
	}
	for _, name := range []string{"link/escape", "leaf-link", "file/child", "dir", "usr/local/bin/entrypoint.sh", "etc/passwd", "usr/lib/startup-runtime/loader.so"} {
		t.Run("reject-"+name, func(t *testing.T) {
			stage := filepath.Join(t.TempDir(), "stage")
			write(stage, "existing/replaced", "must not be sent", 0644)
			write(stage, name, "must not be sent", 0644)
			id := create()
			_, err := copyAgentRoot(ctx, stage, id, 1000, 1000)
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

	// Export must omit host bytes before filtering, while the filter also omits
	// hidden image/template data at mounts. Use the existing real Engine fixture
	// to cover nested/file mounts, aliases, private hardlinks and stopped retrieval.
	t.Run("archive-private-export", func(t *testing.T) {
		fixture, err := os.MkdirTemp(".", ".archive-test-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(fixture) })
		fixture, err = filepath.Abs(fixture)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"host/host-only", "nested/sealed", "file-source"} {
			write(fixture, name, "MOUNTED-HOST-CONTENT-MUST-NOT-BE-READ", 0600)
		}
		stage := filepath.Join(fixture, "stage")
		write(stage, "home/agent/tool dir/literal [*] file", "private bytes", 0750)
		write(stage, "home/agent/project/masked-template", "must not copy or archive", 0644)
		id := create("--mount", directoryBind(filepath.Join(fixture, "host"), "/home/agent/project", false),
			"--mount", directoryBind(filepath.Join(fixture, "nested"), "/home/agent/project/child", true),
			"--mount", directoryBind(filepath.Join(fixture, "file-source"), "/home/agent/file-mount", true),
			"--mount", directoryBind(filepath.Join(fixture, "host"), "/host-alias", true),
			"--tmpfs", "/home/agent/runtime")
		excluded, err := copyAgentRoot(ctx, stage, id, 1000, 1000)
		if err != nil {
			t.Fatal(err)
		}
		docker(nil, "start", "-a", id)
		raw := docker(nil, "export", id)
		if bytes.Contains(raw, []byte("MOUNTED-HOST-CONTENT-MUST-NOT-BE-READ")) || !bytes.Contains(raw, []byte("hidden directory bytes")) || !bytes.Contains(raw, []byte("hidden file bytes")) {
			t.Fatal("raw Docker export did not isolate mounted host data from underlying private contents")
		}
		for _, paths := range [][]string{{"/home/agent", "/etc/chosen", "/missing", "/link/marker", "/host-real"}, {"/home/agent/tool dir"}, {}} {
			s := sessionNames{agentContainer: id, dir: t.TempDir(), archivePaths: paths}
			if err := archiveAgent(ctx, s, excluded); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(s.dir, "artifacts.tar.gz")
			if len(paths) == 0 {
				if _, err := os.Stat(archive); !os.IsNotExist(err) {
					t.Fatalf("disabled collection created an archive: %v", err)
				}
				continue
			}
			f, err := os.Open(archive)
			if err != nil {
				t.Fatal(err)
			}
			info, err := f.Stat()
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("archive permissions: %v (%v)", info, err)
			}
			gz, err := gzip.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			tr := tar.NewReader(gz)
			contents, headers := map[string]string{}, map[string]tar.Header{}
			for {
				h, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, exists := headers[h.Name]; exists || strings.HasPrefix(h.Name, "/") || strings.Contains(h.Name, "..") {
					t.Fatalf("invalid/duplicate archive member: %s", h.Name)
				}
				data, err := io.ReadAll(tr)
				if err != nil {
					t.Fatal(err)
				}
				contents[h.Name], headers[h.Name] = string(data), *h
			}
			if _, err := io.Copy(io.Discard, gz); err != nil {
				t.Fatal(err)
			}
			gz.Close()
			f.Close()
			if contents["home/agent/tool dir/literal [*] file"] != "private bytes" || headers["home/agent/tool dir/literal [*] file"].Mode != 0750 {
				t.Fatalf("lost selected private bytes or permissions: %v", contents)
			}
			if len(paths) > 1 && (contents["home/agent/hardlink"] != "hardlink bytes" || contents["etc/chosen"] != "selected elsewhere" || headers["home/agent/host-link"].Linkname != "/home/agent/project/host-only") {
				t.Fatalf("lost hardlink/selected file/symlink: %v", contents)
			}
			for name := range headers {
				if strings.HasPrefix(name, "home/agent/project") || name == "home/agent/file-mount" || strings.HasPrefix(name, "host-real") || name == "home/agent/pipe" || strings.HasPrefix(name, "link/") || (len(paths) == 1 && !strings.HasPrefix(name, "home/agent/tool dir")) {
					t.Fatalf("retained excluded/unselected member %q", name)
				}
			}
			if _, err := os.Stat(archive + ".partial"); !os.IsNotExist(err) {
				t.Fatalf("successful archive left partial file: %v", err)
			}
		}
		if state := strings.TrimSpace(string(docker(nil, "inspect", "-f", "{{.State.Status}}", id))); state != "exited" {
			t.Fatalf("collection restarted or removed source: %s", state)
		}
	})
}
