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

// Check on the Docker host: Docker's default AppArmor confinement blocks
// securityfs reads in the handler. BPF LSM is the supported-host baseline even
// when this session has no filesystem objects to enroll.
func checkBPFLSM(ctx context.Context) error {
	if out, err := dockerHostScript(ctx, bpfLSMPreflight).CombinedOutput(); err != nil {
		return fmt.Errorf("check BPF LSM: %s: %w", out, err)
	}
	return nil
}

// A missing/unreadable kernel config means unknown, not unsupported.
const bpfLSMPreflight = `
lsm_readable=1
lsms=$(cat /sys/kernel/security/lsm 2>/dev/null) || lsm_readable=0
case ",$lsms," in
  *,bpf,*) ;;
  *)
    config=$(gzip -cd /proc/config.gz 2>/dev/null) || config=
    if [ -z "$config" ]; then
      config=$(cat "/boot/config-$(uname -r)" 2>/dev/null) || config=
    fi
    if printf '%s\n' "$config" | grep -qx 'CONFIG_BPF_LSM=y'; then
      if [ "$lsm_readable" = 0 ]; then
        echo "filesystem policy: kernel supports BPF LSM but /sys/kernel/security/lsm cannot be read; check the Docker host's securityfs mount before changing boot configuration" >&2
      else
        echo "filesystem policy: BPF LSM is supported but not active; add bpf to the boot lsm= list, reboot, and rerun setup" >&2
      fi
    elif [ -n "$config" ]; then
      echo "filesystem policy: current kernel does not support BPF LSM (CONFIG_BPF_LSM=y required); install a supported Ubuntu kernel and reboot" >&2
    else
      echo "filesystem policy: cannot determine kernel BPF LSM support (kernel config unavailable), and bpf is not visible in /sys/kernel/security/lsm; check the Docker host's kernel config and active LSMs before configuring boot" >&2
    fi
    exit 1
    ;;
esac
`

// An empty parent alone is insufficient: kill and drain the entire subtree.
func stopWorkload(s sessionNames) error {
	if s.cgroupParent == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const script = `
test -d "$1"
echo 1 > "$1/cgroup.kill"
while grep -q '^populated 1$' "$1/cgroup.events"; do sleep 0.05; done
grep -q '^populated 0$' "$1/cgroup.events"
`
	if out, err := dockerHostScript(ctx, script, sessionCgroupPath(s)).CombinedOutput(); err != nil {
		return fmt.Errorf("kill and drain workload subtree: %s: %w", out, err)
	}
	return nil
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
