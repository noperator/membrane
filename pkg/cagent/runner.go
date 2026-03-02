package cagent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/creack/pty/v2"
	"golang.org/x/term"
)

func hasSysbox() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	out, err := exec.Command("docker", "info").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "sysbox-runc")
}

// buildArgs constructs the full argument list for docker run.
// passthrough args are appended after the image name as the container command.
func buildArgs(workspaceDir string, m *mounts, cfg *config, passthrough []string) ([]string, error) {
	sysbox := hasSysbox()

	args := []string{"run", "-it", "--rm", "--init"}

	if sysbox {
		args = append(args, "--runtime=sysbox-runc", "-e", "CAGENT_DIND=1")
	}

	args = append(args,
		"--cap-add=NET_ADMIN",
		"--cap-add=NET_RAW",
		"-v", workspaceDir+":/workspace",
	)

	// Add overlay mounts. Readonly first, then shadows (shadows must come
	// after to override).
	for _, mt := range m.items {
		if !mt.empty {
			args = append(args, "-v", mt.hostPath+":"+mt.containerPath+":ro")
		}
	}
	for _, mt := range m.items {
		if mt.empty {
			args = append(args, "-v", mt.hostPath+":"+mt.containerPath+":ro")
		}
	}

	args = append(args, "-v", "cagent-home:/home/cagent")

	// Write merged domains list to a temp file and mount it where
	// firewall.sh expects it.
	domainsFile, err := writeDomains(cfg.Domains)
	if err != nil {
		return nil, err
	}
	args = append(args, "-v", domainsFile+":/usr/local/etc/domains.txt:ro")

	// Extra args from config.
	args = append(args, cfg.ExtraArgs...)

	if title := os.Getenv("CAGENT_TITLE"); title != "" {
		args = append(args, "-e", "CAGENT_TITLE="+title)
	}

	// Image name.
	args = append(args, imageName)

	// Passthrough args (non-flag arguments to cagent binary).
	args = append(args, passthrough...)

	return args, nil
}

// writeDomains writes the domains list to a temp file and returns its path.
// The file is not cleaned up — syscall.Exec replaces this process and the
// OS handles /tmp cleanup.
func writeDomains(domains []string) (string, error) {
	if len(domains) == 0 {
		return "", fmt.Errorf("domains list is empty — add domains to ~/.cagent/config.yaml")
	}
	f, err := os.CreateTemp("", "cagent-domains-")
	if err != nil {
		return "", fmt.Errorf("create domains temp file: %w", err)
	}
	defer f.Close()
	for _, d := range domains {
		fmt.Fprintln(f, d)
	}
	return f.Name(), nil
}

// ExitError carries the exit code from the docker run child process.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("docker exited with code %d", e.Code)
}

// execDocker runs docker as a child process with a PTY, proxies the
// terminal, forwards signals, and returns the child's exit code.
func execDocker(args []string) error {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("docker not found in PATH: %w", err)
	}

	cmd := exec.Command(dockerPath, args...)

	// cagent is assumed to always run interactively. If non-interactive support
	// is needed in the future (e.g. piped stdin via `echo data | cagent -- ...`),
	// detect with term.IsTerminal(int(os.Stdin.Fd())) and branch: skip the PTY,
	// set cmd.Stdin/Stdout/Stderr = os.Stdin/Out/Err directly, and handle signals
	// the same way.
	//
	// Allocate a PTY and start the child process.
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("start docker: %w", err)
	}
	defer ptmx.Close()

	// Propagate terminal resize events.
	resizeCh := make(chan os.Signal, 1)
	signal.Notify(resizeCh, syscall.SIGWINCH)
	defer signal.Stop(resizeCh)
	go func() {
		for range resizeCh {
			if ws, err := pty.GetsizeFull(os.Stdin); err == nil {
				_ = pty.Setsize(ptmx, ws)
			}
		}
	}()
	resizeCh <- syscall.SIGWINCH // set initial size

	// Put the host terminal into raw mode; restore on exit.
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("set terminal raw mode: %w", err)
	}
	defer func() { _ = term.Restore(fd, oldState) }()

	// Forward SIGINT, SIGTERM, and SIGHUP to the child process.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
			_ = cmd.Process.Signal(sig)
		}
	}()

	// Proxy I/O between the host terminal and the PTY.
	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()
	_, _ = io.Copy(os.Stdout, ptmx)

	// Wait for the child to exit.
	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &ExitError{Code: exitErr.ExitCode()}
		}
		return fmt.Errorf("docker run: %w", err)
	}
	return nil
}
