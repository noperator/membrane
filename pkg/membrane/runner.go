package membrane

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
// Returns the args, the generated container name, and any error.
func buildArgs(workspaceDir string, m *mounts, cfg *config, passthrough []string) ([]string, string, error) {
	sysbox := hasSysbox()

	var suffix [8]byte
	_, _ = rand.Read(suffix[:])
	containerName := "membrane-" + hex.EncodeToString(suffix[:])
	args := []string{"run", "-it", "--rm", "--init", "--name", containerName}

	if sysbox {
		args = append(args, "--runtime=sysbox-runc", "-e", "MEMBRANE_DIND=1")
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

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", fmt.Errorf("get home dir: %w", err)
	}
	agentHome := filepath.Join(home, ".membrane", "home")
	if err := os.MkdirAll(agentHome, 0755); err != nil {
		return nil, "", fmt.Errorf("create agent home dir: %w", err)
	}
	args = append(args, "-v", agentHome+":/home/agent")

	// Write merged hostnames list to a temp file and mount it where
	// firewall.sh expects it.
	hostnamesFile, err := writeHostnames(cfg.Hostnames)
	if err != nil {
		return nil, "", err
	}
	args = append(args, "-v", hostnamesFile+":/usr/local/etc/hostnames.txt:ro")

	args = append(args, "-e", "MEMBRANE_RESOLVER="+cfg.Resolver)

	if len(cfg.Cidrs) > 0 {
		args = append(args, "-e", "MEMBRANE_CIDRS="+strings.Join(cfg.Cidrs, ","))
	}

	// Extra args from config.
	args = append(args, cfg.Args...)

	if title := os.Getenv("MEMBRANE_TITLE"); title != "" {
		args = append(args, "-e", "MEMBRANE_TITLE="+title)
	}

	// Image name.
	args = append(args, imageName)

	// Passthrough args (non-flag arguments to membrane binary).
	args = append(args, passthrough...)

	return args, containerName, nil
}

// writeHostnames writes the hostnames list to a temp file and returns its path.
// The file is not cleaned up — syscall.Exec replaces this process and the
// OS handles /tmp cleanup.
func writeHostnames(hostnames []string) (string, error) {
	if len(hostnames) == 0 {
		return "", fmt.Errorf("hostnames list is empty — add hostnames to ~/.membrane/config.yaml")
	}
	f, err := os.CreateTemp("", "membrane-hostnames-")
	if err != nil {
		return "", fmt.Errorf("create hostnames temp file: %w", err)
	}
	defer f.Close()
	for _, d := range hostnames {
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

// execDocker runs docker as a child process, proxies the terminal,
// forwards signals, and returns the child's exit code.
//
// When stdin is a terminal the child gets a PTY (interactive mode).
// Otherwise stdin/stdout/stderr are wired directly so that output can
// be captured by scripts and tools like GNU parallel.
func execDocker(args []string) error {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("docker not found in PATH: %w", err)
	}

	interactive := term.IsTerminal(int(os.Stdin.Fd()))

	if !interactive {
		// Strip -t from docker args; a TTY cannot be allocated without
		// a terminal on the host side.
		for i, a := range args {
			if a == "-it" {
				args[i] = "-i"
				break
			}
		}

		cmd := exec.Command(dockerPath, args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("start docker: %w", err)
		}

		// Forward SIGINT, SIGTERM, and SIGHUP to the child process.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		defer signal.Stop(sigCh)
		go func() {
			for sig := range sigCh {
				_ = cmd.Process.Signal(sig)
			}
		}()

		if err := cmd.Wait(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return &ExitError{Code: exitErr.ExitCode()}
			}
			return fmt.Errorf("docker run: %w", err)
		}
		return nil
	}

	// Interactive path: allocate a PTY.
	cmd := exec.Command(dockerPath, args...)

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
