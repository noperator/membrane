package membrane

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func archiveStreamFixture(t *testing.T, dir string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, "stream.tar"))
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	const size = 256 * 1024
	err = tw.WriteHeader(&tar.Header{Name: "home/agent/private", Mode: 0600, Size: size})
	if err == nil {
		_, err = io.CopyN(tw, rand.Reader, size)
	}
	if err := errors.Join(err, tw.Close(), f.Close()); err != nil {
		t.Fatal(err)
	}
}

// Collection has its own outcome: a failed producer must leave only a partial
// file, fail an otherwise successful command, and preserve an existing workload
// exit code. Exercise the lifecycle rather than only testing tar filtering.
func TestAgentArchiveOutcome(t *testing.T) {
	for _, test := range []struct {
		workloadExit int
		completeTar  bool
	}{{0, false}, {37, false}, {0, true}, {37, true}} {
		t.Run(strconv.Itoa(test.workloadExit)+"/complete-tar="+strconv.FormatBool(test.completeTar), func(t *testing.T) {
			dir := t.TempDir()
			archiveStreamFixture(t, dir)
			t.Setenv("TEST_ROOT", dir)
			t.Setenv("WORKLOAD_EXIT", strconv.Itoa(test.workloadExit))
			t.Setenv("COMPLETE_TAR", strconv.FormatBool(test.completeTar))
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			hostFixtureCommand(t, dir, "docker", `
case "$1" in
  start) exit "$WORKLOAD_EXIT" ;;
  wait) exec sleep 30 ;;
  stop) touch "$TEST_ROOT/stopped" ;;
  inspect)
    if [ "$2" = '-f' ]; then echo true
    else echo '[{"Id":"source","State":{"Status":"exited"}}]'; fi ;;
  export)
    test -f "$TEST_ROOT/stopped" || exit 91
    if [ "$COMPLETE_TAR" = true ]; then cat "$TEST_ROOT/stream.tar"; else printf 'broken stream'; fi
    echo 'producer fixture failed' >&2
    exit 7 ;;
  *) exit 92 ;;
esac`)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s := sessionNames{dir: dir, agentContainer: "source", handlerContainer: "handler", archivePaths: []string{"/home/agent"}}
			err := runAgent(ctx, s, []string{"start"})
			if err == nil || !strings.Contains(err.Error(), "producer fixture failed") {
				t.Fatalf("lost collection failure: %v", err)
			}
			var exitErr *ExitError
			if test.workloadExit != 0 && (!errors.As(err, &exitErr) || exitErr.Code != test.workloadExit) {
				t.Fatalf("lost workload exit status: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "artifacts.tar.gz")); !os.IsNotExist(err) {
				t.Fatalf("published failed export: %v", err)
			}
			info, err := os.Stat(filepath.Join(dir, "artifacts.tar.gz.partial"))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("missing private partial: %v (%v)", info, err)
			}
		})
	}
}

// Cancellation must interrupt a blocked export producer after stopping writers,
// retain the partial result, and return control to the caller's resource cleanup.
func TestArchiveCancellation(t *testing.T) {
	dir := t.TempDir()
	archiveStreamFixture(t, dir)
	t.Setenv("TEST_ROOT", dir)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	hostFixtureCommand(t, dir, "docker", `
case "$1" in
  inspect) echo '[{"Id":"source","State":{"Status":"exited"}}]' ;;
  stop) touch "$TEST_ROOT/stopped" ;;
  export) cat "$TEST_ROOT/stream.tar"; touch "$TEST_ROOT/exporting"; exec sleep 30 ;;
  *) exit 92 ;;
esac`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- archiveAgent(ctx, sessionNames{dir: dir, agentContainer: "source", archivePaths: []string{"/home/agent"}}, nil)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "exporting")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("collector never started export")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Even after tar EOF, a blocked producer must remain cancellable. Selected
	// bytes must already be on disk instead of waiting in a whole-stream buffer.
	info, err := os.Stat(filepath.Join(dir, "artifacts.tar.gz.partial"))
	if err != nil || info.Size() < 65536 {
		t.Fatalf("archive did not stream before producer exit: %v (%v)", info, err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("export producer did not stop")
	}
	for _, name := range []string{"stopped", "artifacts.tar.gz.partial"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "artifacts.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("published interrupted export: %v", err)
	}
}

// A real file-write error must cancel export and keep only the partial. Limit
// just a subprocess's file size so this works without filling any real disk or
// adding a production writer-injection interface solely for tests.
func TestArchiveWriteFailure(t *testing.T) {
	if dir := os.Getenv("MEMBRANE_ARCHIVE_WRITE_FIXTURE"); dir != "" {
		signal.Ignore(syscall.SIGXFSZ)
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 65536, Max: 65536}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := archiveAgent(ctx, sessionNames{dir: dir, agentContainer: "source", archivePaths: []string{"/home/agent"}}, nil)
		if !errors.Is(err, syscall.EFBIG) || ctx.Err() != nil {
			t.Fatalf("lost file-write failure or producer did not stop: %v (context %v)", err, ctx.Err())
		}
		return
	}
	dir := t.TempDir()
	archiveStreamFixture(t, dir)
	t.Setenv("TEST_ROOT", dir)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	hostFixtureCommand(t, dir, "docker", `
case "$1" in
  inspect) echo '[{"Id":"source","State":{"Status":"exited"}}]' ;;
  stop) exit 0 ;;
  export) exec cat "$TEST_ROOT/stream.tar" ;;
  *) exit 92 ;;
esac`)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestArchiveWriteFailure$", "-test.timeout=10s")
	child.Env = append(os.Environ(), "MEMBRANE_ARCHIVE_WRITE_FIXTURE="+dir)
	if out, err := child.CombinedOutput(); err != nil {
		t.Fatalf("limited writer: %s (%v)", out, err)
	}
	info, err := os.Stat(filepath.Join(dir, "artifacts.tar.gz.partial"))
	if err != nil || info.Size() == 0 || info.Size() > 65536 || info.Mode().Perm() != 0600 {
		t.Fatalf("missing private partial at failed write: %v (%v)", info, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "artifacts.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("published failed output: %v", err)
	}
}

func TestAgentDockerArguments(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	workspace := filepath.Join(t.TempDir(), "workspace with spaces")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	workspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config{Args: []string{"--cgroup-parent=/configured-parent", "--rm"}}
	// A merged readonly workspace must reach Docker without losing its workdir
	// or adding a second bind for the same destination.
	for _, test := range []struct{ parent, mode string }{{"/membrane-test", "rw"}, {"/membrane-test", "ro"}, {"", "rw"}} {
		parent := test.parent
		mounts, _, err := resolveMountsWithWarnings(t, workspace, []directoryMount{{Path: ".", Mode: test.mode}})
		if err != nil {
			t.Fatal(err)
		}
		mounts = append(mounts, directoryMount{Path: "/extra with spaces", Mode: "ro"})
		args, err := buildAgentArgs(workspace, cfg, nil,
			sessionNames{cgroupParent: parent, directoryMounts: mounts}, "172.20.0.2", false)
		if parent == "" {
			if err == nil {
				t.Fatal("accepted a workload without a session cgroup")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "empty-file") || strings.Contains(joined, "empty-dir") {
			t.Fatalf("per-path filesystem policy mount returned: %v", args)
		}
		mount := slices.Index(args, "--mount")
		workdir := slices.Index(args, "--workdir")
		wantBind := "type=bind,src=" + workspace + ",dst=" + workspace
		if test.mode == "ro" {
			wantBind += ",readonly"
		}
		if mount < 0 || args[mount+1] != wantBind || strings.Count(joined, "dst="+workspace) != 1 || workdir < 0 || args[workdir+1] != workspace {
			t.Fatalf("workspace mount and working directory must preserve the host path: %v", args)
		}
		if !slices.Contains(args, "type=bind,src=/extra with spaces,dst=/extra with spaces,readonly") {
			t.Fatalf("missing readonly additional mount argument: %v", args)
		}
		if args[0] != "create" || !strings.Contains(joined, "--cgroup-parent="+parent) {
			t.Fatalf("missing traced create/parent: %v", args)
		}
		if strings.LastIndex(joined, "--cgroup-parent=") != strings.Index(joined, "--cgroup-parent="+parent) {
			t.Fatalf("configuration overrode session parent: %v", args)
		}
		// Private state must survive workload exit until owned cleanup runs;
		// a legacy home bind would also silently restore previous agent writes.
		if strings.Contains(joined, ":/home/agent") || slices.Index(args, "--rm=false") < slices.Index(args, "--rm") {
			t.Fatalf("private home or explicit removal was overridden: %v", args)
		}
	}
}

// A generated file below an explicit mount would mask the user's live file and
// could make Docker create its mountpoint in host data. Cover supported flag
// spellings, while leaving Docker's existing user-mount conflict rules intact.
func TestAgentInstructionMountPrecedence(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	hostFixtureCommand(t, dir, "docker", `
test "$1 $2 $3 $4" = 'inspect -f {{json .Mounts}} fixture' || exit 99
echo '[{"Destination":"/home/agent"}]'`)
	for _, args := range [][]string{
		{"--mount", "type=bind,src=/source,dst=/home/agent"},
		{"--mount=type=bind,src=/source,destination=/home/agent/.codex"},
		{"--mount", "type=volume,src=codex,target=/home/agent/.codex/AGENTS.md"},
		{"-v", "/source:/home/agent"},
		{"-v/source:/home/agent"},
		{"--volume=/source:/home/agent:ro"},
		{"--tmpfs", "/home/agent:rw"},
		{"--volumes-from=fixture:ro"},
	} {
		s := sessionNames{cgroupParent: "/test", agentFileMounts: []agentFileMount{
			{"/generated-codex", "/home/agent/.codex/AGENTS.md"},
			{"/generated-membrane", "/etc/membrane/AGENTS.md"},
		}}
		got, err := buildAgentArgs("/workspace", &config{Args: args}, nil, s, "", false)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(got, " ")
		if strings.Contains(joined, "src=/generated-codex") || !strings.Contains(joined, "src=/generated-membrane") {
			t.Errorf("incorrect implicit mount masking for %v: %v", args, got)
		}
	}
}

// Copy-in can outlast handler readiness. Required-service death must interrupt
// preparation and retain the actual failure, never launch an unprotected agent.
func TestHandlerFailureDuringAgentPreparation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TEST_ROOT", dir)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	hostFixtureCommand(t, dir, "docker", `
case "$1" in
  create) exit 0 ;;
  inspect) touch "$TEST_ROOT/copying"; exec sleep 30 ;;
  wait) while [ ! -e "$TEST_ROOT/copying" ]; do sleep .01; done; echo 137 ;;
  start) touch "$TEST_ROOT/started" ;;
esac`)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := runAgent(ctx, sessionNames{handlerContainer: "handler", agentContainer: "agent"}, []string{"create"})
	if err == nil || !strings.Contains(err.Error(), "handler exited during session: 137") || ctx.Err() != nil {
		t.Fatalf("handler failure did not interrupt copy-in: %v (context %v)", err, ctx.Err())
	}
	if _, err := os.Stat(filepath.Join(dir, "started")); !os.IsNotExist(err) {
		t.Fatal("workload started after handler failure")
	}
}

// Handler death can race with workload exit. Preserve both the workload status
// and service diagnostics regardless of which waiter completes first.
func TestHandlerFailurePreservesWorkloadExit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TEST_ROOT", dir)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	hostFixtureCommand(t, dir, "docker", `
case "$1" in
  start) touch "$TEST_ROOT/started"; exit 37 ;;
  wait) while [ ! -e "$TEST_ROOT/started" ]; do sleep .01; done; echo 1 ;;
  inspect) echo false ;;
  logs) echo 'dns-proxy exited unexpectedly' ;;
  kill) exit 0 ;;
  *) exit 92 ;;
esac`)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := runAgent(ctx, sessionNames{agentContainer: "agent", handlerContainer: "handler"}, []string{"start"})
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 37 || !strings.Contains(err.Error(), "dns-proxy exited unexpectedly") {
		t.Fatalf("lost original failure or service diagnostics: %v", err)
	}
}

// An old or damaged image must fail with a rebuild command before user code can
// run. Exercise the launcher, including cancellation of its handler watcher.
func TestAgentRequiresStartupManifest(t *testing.T) {
	for _, mode := range []string{"missing", "invalid-tar", "symlink", "incomplete", "invalid-path"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("TEST_ROOT", dir)
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			if mode != "missing" {
				f, err := os.Create(filepath.Join(dir, "manifest.tar"))
				if err != nil {
					t.Fatal(err)
				}
				if mode == "invalid-tar" {
					_, err = f.WriteString("not an archive")
				} else {
					data := "/usr/local/share/membrane/startup-paths\n"
					if mode == "invalid-path" {
						data += "/usr/local/bin/entrypoint.sh\n../outside\n"
					}
					header := &tar.Header{Name: "startup-paths", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(data))}
					if mode == "symlink" {
						header.Typeflag, header.Linkname, header.Size, data = tar.TypeSymlink, "/untrusted", 0, ""
					}
					tw := tar.NewWriter(f)
					if err = tw.WriteHeader(header); err == nil {
						_, err = tw.Write([]byte(data))
					}
					if closeErr := tw.Close(); err == nil {
						err = closeErr
					}
				}
				if closeErr := f.Close(); err == nil {
					err = closeErr
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			hostFixtureCommand(t, dir, "docker", `
case "$1" in
  create) exit 0 ;;
  inspect) echo '[{"ID":"agent","State":{"Status":"created"}}]' ;;
  cp) test "$2" = 'agent:/usr/local/share/membrane/startup-paths' || exit 99
      cat "$TEST_ROOT/manifest.tar" ;;
  wait) exec sleep 30 ;;
  start) touch "$TEST_ROOT/started" ;;
  *) exit 99 ;;
esac`)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := runAgent(ctx, sessionNames{handlerContainer: "handler", agentContainer: "agent"}, []string{"create"})
			if err == nil || !strings.Contains(err.Error(), "startup path") || !strings.Contains(err.Error(), "docker build -t membrane-agent docker/agent") || ctx.Err() != nil {
				t.Fatalf("missing actionable manifest failure: %v (context %v)", err, ctx.Err())
			}
			if _, err := os.Stat(filepath.Join(dir, "started")); !os.IsNotExist(err) {
				t.Fatal("workload started without a valid startup manifest")
			}
		})
	}
}

// Exercise startup arguments and teardown through fixture Docker/host commands.
// No real cgroup, network, container, or sudo operation is performed.
func TestSessionScopeAndTeardown(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native host command fixtures")
	}
	for _, mode := range []string{"network-only", "policy", "tracing", "drain-failure"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("HOME", dir)
			t.Setenv("TEST_ROOT", dir)
			t.Setenv("TEST_CGROUP", filepath.Join(dir, "cgroup"))
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			hostFixtureCommand(t, dir, "sudo", `
[ "$1" != iptables ] || exit 0
[ "$1" != -- ] || shift
exec "$@"`)
			hostFixtureCommand(t, dir, "mkdir", `
[ "$1" = /sys/fs/cgroup/membrane-fixture ] || exit 99
/bin/mkdir "$TEST_CGROUP"
echo 'populated 0' > "$TEST_CGROUP/cgroup.events"
touch "$TEST_CGROUP/cgroup.kill"`)
			hostFixtureCommand(t, dir, "rmdir", `
echo remove-cgroup >> "$TEST_ROOT/calls"
test "$1" = /sys/fs/cgroup/membrane-fixture`)
			hostFixtureCommand(t, dir, "sh", `
echo kill-and-drain >> "$TEST_ROOT/calls"
exec /bin/sh -seu -- "$TEST_CGROUP"`)
			hostFixtureCommand(t, dir, "docker", `
echo "docker $*" >> "$TEST_ROOT/calls"
case "$1 $2" in
  'info --format') echo '2 cgroupfs' ;;
  'network create') echo abcdef0123456789 ;;
  'run -d') printf '%s\n' "$@" > "$TEST_ROOT/handler-args" ;;
  'logs -f') exec sleep 300 ;;
  'inspect -f') echo 172.20.0.2 ;;
esac`)
			s, err := newSession(filepath.Join(dir, ".membrane"))
			if err != nil {
				t.Fatal(err)
			}
			s.id, s.agentContainer, s.handlerContainer = "fixture", "agent", "handler"
			s.internalNetwork, s.externalNetwork, s.caVolume = "internal", "external", "ca"
			s.policyRoots = map[int]string{0: dir, 2: "/extra with spaces"}
			policy := ""
			if mode == "policy" {
				policy = filepath.Join(dir, "policy.json")
			}
			cleanup, _, err := startSession(context.Background(), &s, &config{}, mode == "tracing", filepath.Join(dir, "trace.gz"), policy)
			if err != nil {
				t.Fatal(err)
			}
			args, err := os.ReadFile(filepath.Join(dir, "handler-args"))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"--cgroupns=private", "type=bind,src=/sys/fs/cgroup/membrane-fixture,dst=/workload-cgroup", "MEMBRANE_TARGET_CGROUP=/workload-cgroup"} {
				if !strings.Contains(string(args), want) {
					t.Errorf("missing scoped mount setting %q: %s", want, args)
				}
			}
			for _, forbidden := range []string{"/policy-pins", "/sys/fs/bpf", "MEMBRANE_POLICY_PINS", ":/sys/fs/cgroup"} {
				if strings.Contains(string(args), forbidden) {
					t.Errorf("unexpected handler setting %q: %s", forbidden, args)
				}
			}
			if strings.Contains(string(args), "--cap-add=BPF") != (mode == "policy" || mode == "tracing") {
				t.Errorf("BPF capabilities do not match requested features: %s", args)
			}
			if mode == "policy" {
				for _, want := range []string{"type=bind,src=" + dir + ",dst=/policy-roots/0,readonly", "type=bind,src=/extra with spaces,dst=/policy-roots/2,readonly", "MEMBRANE_POLICY_ROOTS=/policy-roots"} {
					if !strings.Contains(string(args), want) {
						t.Errorf("missing trusted root %q: %s", want, args)
					}
				}
			}
			if mode == "drain-failure" {
				if err := os.WriteFile(filepath.Join(dir, "cgroup/cgroup.events"), []byte("invalid\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err = cleanup()
			calls, readErr := os.ReadFile(filepath.Join(dir, "calls"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			// A second teardown must neither touch released resources nor try to
			// recompress an already retained log. Failed teardown stays fail-closed.
			again := cleanup()
			after, readErr := os.ReadFile(filepath.Join(dir, "calls"))
			if readErr != nil || again != err || string(after) != string(calls) {
				t.Fatalf("repeated cleanup changed resources/result: first=%v second=%v read=%v\n%s", err, again, readErr, after)
			}
			if mode == "drain-failure" {
				if err == nil || strings.Contains(string(calls), "docker stop") || strings.Contains(string(calls), "remove-cgroup") {
					t.Fatalf("released security resources without draining: %v\n%s", err, calls)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			last := -1
			for _, step := range []string{"docker rm -f agent", "kill-and-drain", "docker stop -t 10 handler", "docker rm handler", "remove-cgroup", "docker network rm internal", "docker network rm external", "docker volume rm ca"} {
				next := strings.Index(string(calls), step)
				if next <= last {
					t.Fatalf("teardown step %q missing/out of order:\n%s", step, calls)
				}
				last = next
			}
		})
	}
}

// Session inputs can contain credentials. Distinct private directories must
// survive another session's runtime cleanup without losing retained outputs.
func TestSessionFilesIsolation(t *testing.T) {
	dir := t.TempDir()
	first, err := newSession(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newSession(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.id == second.id || first.dir == second.dir {
		t.Fatal("sessions share an identity or directory")
	}
	for _, s := range []sessionNames{first, second} {
		for _, path := range []string{s.dir, s.logsDir, s.runtimeDir} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0700 {
				t.Fatalf("session directory is not private: %s (%v)", path, err)
			}
		}
		network, err := writeNetworkRulesFile(s.runtimeDir, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := writePolicyFile(s.runtimeDir, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{network, policy} {
			info, err := os.Stat(path)
			if err != nil || filepath.Dir(path) != s.runtimeDir || info.Mode().Perm() != 0600 {
				t.Fatalf("generated input is not private session data: %s (%v)", path, err)
			}
		}
		log := filepath.Join(s.logsDir, "handler.log")
		if err := os.WriteFile(log, []byte(s.id), 0600); err != nil {
			t.Fatal(err)
		}
		if err := gzipFile(log + ".gz"); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(first.runtimeDir); err != nil {
		t.Fatal(err)
	}
	for _, s := range []sessionNames{first, second} {
		log := filepath.Join(s.logsDir, "handler.log.gz")
		info, err := os.Stat(log)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("retained log is not private: %s (%v)", log, err)
		}
		f, err := os.Open(log)
		if err != nil {
			t.Fatal(err)
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			t.Fatal(err)
		}
		data, err := io.ReadAll(gz)
		gz.Close()
		f.Close()
		if err != nil || string(data) != s.id {
			t.Fatalf("retained log damaged or overwritten: %q (%v)", data, err)
		}
	}
	entries, err := os.ReadDir(second.runtimeDir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("cleanup affected the other session: %v (%v)", entries, err)
	}
}
