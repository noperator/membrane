package membrane

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestAgentDockerArguments(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	workspace := filepath.Join(t.TempDir(), "workspace with spaces")
	cfg := &config{Args: []string{"--cgroup-parent=/configured-parent"}}
	for _, parent := range []string{"/membrane-test", ""} {
		args, err := buildAgentArgs(workspace, cfg, nil,
			sessionNames{cgroupParent: parent}, "172.20.0.2", false)
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
		mount := slices.Index(args, "-v")
		workdir := slices.Index(args, "--workdir")
		if mount < 0 || args[mount+1] != workspace+":"+workspace || workdir < 0 || args[workdir+1] != workspace {
			t.Fatalf("workspace mount and working directory must preserve the host path: %v", args)
		}
		if args[0] != "create" || !strings.Contains(joined, "--cgroup-parent="+parent) {
			t.Fatalf("missing traced create/parent: %v", args)
		}
		if strings.LastIndex(joined, "--cgroup-parent=") != strings.Index(joined, "--cgroup-parent="+parent) {
			t.Fatalf("configuration overrode session parent: %v", args)
		}
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
			s := sessionNames{id: "fixture", agentContainer: "agent", handlerContainer: "handler",
				internalNetwork: "internal", externalNetwork: "external", caVolume: "ca"}
			policy := ""
			if mode == "policy" {
				policy = filepath.Join(dir, "policy.json")
			}
			cleanup, _, err := startSession(context.Background(), &s, &config{}, mode == "tracing", filepath.Join(dir, "trace.gz"), dir, policy)
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
