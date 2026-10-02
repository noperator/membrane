package membrane

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func dockerHostCommand(ctx context.Context, args ...string) *exec.Cmd {
	if runtime.GOOS == "darwin" {
		return exec.CommandContext(ctx, "colima", append([]string{"ssh", "--profile", "membrane", "--", "sudo", "-n", "--"}, args...)...)
	}
	if os.Geteuid() == 0 {
		return exec.CommandContext(ctx, args[0], args[1:]...)
	}
	// Like dependency installation and the DOCKER-USER rule, let sudo use the
	// controlling terminal for authentication. Stdin may carry a host script.
	return exec.CommandContext(ctx, "sudo", append([]string{"--"}, args...)...)
}

func sessionCgroupPath(s sessionNames) string {
	return "/sys/fs/cgroup/" + strings.TrimPrefix(s.cgroupParent, "/")
}

// Send scripts over stdin: Colima/SSH command forwarding need not preserve a
// multi-line shell program as one argument. Session paths are positional data.
func dockerHostScript(ctx context.Context, script string, args ...string) *exec.Cmd {
	cmd := dockerHostCommand(ctx, append([]string{"sh", "-seu", "--"}, args...)...)
	cmd.Stdin = strings.NewReader(script)
	return cmd
}

func createPolicyPins(ctx context.Context, s *sessionNames) error {
	path := "/sys/fs/bpf/membrane/" + s.id
	// Check on the Docker host: the handler keeps Docker's default AppArmor
	// confinement, which blocks reads of /sys/kernel/security/lsm.
	const script = `
case ",$(cat /sys/kernel/security/lsm)," in
  *,bpf,*) ;; *) echo "filesystem policy requires active BPF LSM; enable bpf in the boot lsm= list and reboot" >&2; exit 1;;
esac
[ "$(stat -f -c %T /sys/fs/bpf)" = bpf_fs ] || { echo "filesystem policy requires mounted bpffs at /sys/fs/bpf" >&2; exit 1; }
mkdir -p /sys/fs/bpf/membrane
mkdir -m 700 "$1"
`
	if out, err := dockerHostScript(ctx, script, path).CombinedOutput(); err != nil {
		return fmt.Errorf("prepare mandatory filesystem policy: %s: %w", out, err)
	}
	s.policyPins = path
	return nil
}

// An empty parent alone is insufficient: kill and check the entire subtree.
// Failure deliberately retains enforcement, handler, and cgroup for recovery.
func stopPolicyWorkload(s sessionNames) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Do not unpin while Docker could still start/restart a created container.
	// A failed rm followed by an unavailable daemon cannot establish this barrier.
	out, err := exec.CommandContext(ctx, "docker", "container", "ls", "-aq", "--filter", "name=^/"+s.agentContainer+"$").CombinedOutput()
	if err != nil || len(strings.TrimSpace(string(out))) != 0 {
		return fmt.Errorf("cannot confirm agent container removal: %s (%v)", out, err)
	}
	const script = `
test -d "$1"
echo 1 > "$1/cgroup.kill"
while grep -q '^populated 1$' "$1/cgroup.events"; do sleep 0.05; done
grep -q '^populated 0$' "$1/cgroup.events"
# Only this session's flat, exclusively created pin directory is removed.
find "$2" -mindepth 1 -maxdepth 1 -type f -delete
`
	if out, err := dockerHostScript(ctx, script, sessionCgroupPath(s), s.policyPins).CombinedOutput(); err != nil {
		return fmt.Errorf("stop workload subtree before unpinning: %s: %w", out, err)
	}
	return nil
}

func removePolicyDirectory(s sessionNames) {
	if s.policyPins == "" || s.preservePolicy {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := dockerHostCommand(ctx, "rmdir", s.policyPins).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: retained policy directory %s: %s: %v\n", s.policyPins, out, err)
	}
}

func writePolicyFile(entries []filesystemPolicyEntry) (string, error) {
	home, err := membraneHome()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "tmp")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "membrane-policy-*.json")
	if err != nil {
		return "", err
	}
	err = json.NewEncoder(f).Encode(entries)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
