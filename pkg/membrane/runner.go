package membrane

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty/v2"
	"golang.org/x/term"
)

// writeAllowFile serialises allow rules to a temp file and returns its path.
// The caller is responsible for removing the file when done.
func writeAllowFile(allow []AllowRule) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	dir := filepath.Join(home, ".membrane", "tmp")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create tmp dir: %w", err)
	}
	f, err := os.CreateTemp(dir, "membrane-allow-*.json")
	if err != nil {
		return "", fmt.Errorf("create allow file: %w", err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(allow); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("write allow file: %w", err)
	}
	return f.Name(), nil
}

func hasSysbox() bool {
	out, err := exec.Command("docker", "info", "--format",
		"{{json .Runtimes}}").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), `"sysbox-runc"`)
}

type sessionNames struct {
	id               string
	agentContainer   string
	handlerContainer string
	internalNetwork  string
	externalNetwork  string
	caVolume         string
}

func newSessionNames() sessionNames {
	var b [8]byte
	_, _ = rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	return sessionNames{
		id:               id,
		agentContainer:   "membrane-agent-" + id,
		handlerContainer: "membrane-handler-" + id,
		internalNetwork:  "membrane-internal-" + id,
		externalNetwork:  "membrane-external-" + id,
		caVolume:         "membrane-ca-" + id,
	}
}

// brNetfilterLoaded reports whether the br_netfilter kernel module is
// currently loaded. When loaded, bridge traffic passes through the host's
// iptables FORWARD chain, which can cause DOCKER-ISOLATION-STAGE-1 to drop
// membrane's proxied traffic. See injectDockerUserRule.
func brNetfilterLoaded() bool {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "br_netfilter ") {
			return true
		}
	}
	return false
}

// injectDockerUserRule inserts an iptables rule into DOCKER-USER that allows
// forwarded traffic from the membrane internal bridge. This is necessary when
// br_netfilter is loaded on the host (Docker versions prior to 27.3.1 loaded
// it automatically), which causes DOCKER-ISOLATION-STAGE-1 to drop packets
// from --internal networks destined for external IPs — silently breaking
// membrane's transparent proxy. DOCKER-USER is evaluated before
// DOCKER-ISOLATION-STAGE-1, so an ACCEPT here prevents the DROP from firing.
//
// Returns ("", nil) if sudo is not available — non-fatal.
func injectDockerUserRule(internalNetworkID string) (string, error) {
	if len(internalNetworkID) < 12 {
		return "", fmt.Errorf("unexpected network ID %q", internalNetworkID)
	}
	bridge := "br-" + internalNetworkID[:12]
	if _, err := exec.LookPath("sudo"); err != nil {
		return "", nil
	}
	if err := exec.Command("sudo", "iptables", "--wait", "-I", "DOCKER-USER",
		"-i", bridge, "-j", "ACCEPT").Run(); err != nil {
		return "", fmt.Errorf("inject DOCKER-USER rule: %w", err)
	}
	return bridge, nil
}

func removeDockerUserRule(bridge string) {
	if bridge == "" {
		return
	}
	// Ignore errors — rule may already be gone if Docker restarted
	_ = exec.Command("sudo", "iptables", "--wait", "-D", "DOCKER-USER",
		"-i", bridge, "-j", "ACCEPT").Run()
}

// startSession creates per-session networks, starts the handler container,
// waits for it to signal ready, and returns a cleanup func and the handler's
// IP on the internal network.
func startSession(s sessionNames, cfg *config) (func(), string, error) {
	cleanup := func() {
		_ = exec.Command("docker", "stop", "-t", "2", s.handlerContainer).Run()
		_ = exec.Command("docker", "rm", s.handlerContainer).Run()
		_ = exec.Command("docker", "network", "rm", s.internalNetwork).Run()
		_ = exec.Command("docker", "network", "rm", s.externalNetwork).Run()
		_ = exec.Command("docker", "volume", "rm", s.caVolume).Run()
	}

	if out, err := exec.Command("docker", "volume", "create",
		s.caVolume).CombinedOutput(); err != nil {
		return cleanup, "", fmt.Errorf("create ca volume %s: %s: %w",
			s.caVolume, out, err)
	}

	if out, err := exec.Command("docker", "network", "create",
		s.externalNetwork).CombinedOutput(); err != nil {
		return cleanup, "", fmt.Errorf("create network %s: %s: %w",
			s.externalNetwork, out, err)
	}

	out, err := exec.Command("docker", "network", "create",
		"--internal", s.internalNetwork).CombinedOutput()
	if err != nil {
		return cleanup, "", fmt.Errorf("create network %s: %s: %w",
			s.internalNetwork, out, err)
	}
	networkID := strings.TrimSpace(string(out))

	var bridge string
	if brNetfilterLoaded() {
		fmt.Fprintf(os.Stderr, "membrane: br_netfilter detected; requesting sudo to add iptables rule for transparent proxy\n")
		bridge, err = injectDockerUserRule(networkID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not inject DOCKER-USER rule: %v\n", err)
		}
	}
	origCleanup := cleanup
	cleanup = func() {
		removeDockerUserRule(bridge)
		origCleanup()
	}

	allowFile, err := writeAllowFile(cfg.Allow)
	if err != nil {
		return cleanup, "", fmt.Errorf("write allow file: %w", err)
	}
	prevCleanup := cleanup
	cleanup = func() {
		prevCleanup()
		os.Remove(allowFile)
	}

	handlerArgs := []string{
		"run", "-d",
		"--name", s.handlerContainer,
		"--network", s.externalNetwork,
		"--cap-add=NET_ADMIN",
		"--sysctl", "net.ipv4.ip_forward=1",
		"-v", s.caVolume + ":/membrane-ca",
		"-v", allowFile + ":/etc/membrane/allow.json:ro",
		"-e", "MEMBRANE_DNS_RESOLVER=" + cfg.dnsResolver(),
		"-e", fmt.Sprintf("MEMBRANE_SSL_INSECURE=%v", cfg.SSLInsecure),
		handlerImageName,
	}

	if out, err := exec.Command("docker", handlerArgs...).CombinedOutput(); err != nil {
		return cleanup, "", fmt.Errorf("start handler: %s: %w", out, err)
	}

	if out, err := exec.Command("docker", "network", "connect",
		s.internalNetwork, s.handlerContainer).CombinedOutput(); err != nil {
		return cleanup, "", fmt.Errorf("connect handler to internal network: %s: %w", out, err)
	}

	// Wait for handler ready signal (timeout 30s).
	for i := 0; i < 30; i++ {
		if exec.Command("docker", "exec", s.handlerContainer,
			"test", "-f", "/tmp/handler-ready").Run() == nil {
			break
		}
		if i == 29 {
			logs, _ := exec.Command("docker", "logs",
				s.handlerContainer).CombinedOutput()
			return cleanup, "", fmt.Errorf(
				"handler did not become ready within 30s\nHandler logs:\n%s", logs)
		}
		time.Sleep(time.Second)
	}

	// Persist handler logs to ~/.membrane/logs/<handler-container>.log
	// during the session, gzipped on cleanup. Mirrors the trace file
	// pattern in tracer.go — preserves logs after the session ends so
	// failures can be investigated post-hoc.
	home, err := os.UserHomeDir()
	if err != nil {
		return cleanup, "", fmt.Errorf("get home dir: %w", err)
	}
	logDir := filepath.Join(home, ".membrane", "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return cleanup, "", fmt.Errorf("create handler log dir: %w", err)
	}
	logPath := filepath.Join(logDir, s.handlerContainer+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return cleanup, "", fmt.Errorf("create handler log file: %w", err)
	}

	logCmd := exec.Command("docker", "logs", "-f", s.handlerContainer)
	logCmd.Stdout = logFile
	logCmd.Stderr = logFile
	if err := logCmd.Start(); err != nil {
		logFile.Close()
		return cleanup, "", fmt.Errorf("start handler log capture: %w", err)
	}

	prevCleanup2 := cleanup
	cleanup = func() {
		if logCmd.Process != nil {
			_ = logCmd.Process.Kill()
		}
		_ = logCmd.Wait()
		logFile.Close()
		if err := gzipFile(logPath + ".gz"); err == nil {
			os.Remove(logPath)
		}
		prevCleanup2()
	}

	out, err = exec.Command("docker", "inspect", "-f",
		fmt.Sprintf("{{(index .NetworkSettings.Networks %q).IPAddress}}",
			s.internalNetwork),
		s.handlerContainer).Output()
	if err != nil {
		return cleanup, "", fmt.Errorf("inspect handler IP: %w", err)
	}
	gatewayIP := strings.TrimSpace(string(out))
	if gatewayIP == "" {
		return cleanup, "", fmt.Errorf("handler has no IP on %s", s.internalNetwork)
	}

	return cleanup, gatewayIP, nil
}

// buildAgentArgs constructs the full argument list for docker run of the agent.
// passthrough args are appended after the image name as the container command.
func buildAgentArgs(workspaceDir string, m *mounts, cfg *config, passthrough []string, s sessionNames, gatewayIP string) ([]string, error) {
	sysbox := hasSysbox()

	args := []string{"run", "-it", "--rm", "--init", "--name", s.agentContainer}

	if sysbox {
		args = append(args, "--runtime=sysbox-runc", "-e", "MEMBRANE_DIND=1")
	}

	args = append(args,
		"--cap-add=NET_ADMIN",
		"--cap-add=CAP_SETPCAP",
		"--network", s.internalNetwork,
		"-e", "MEMBRANE_GATEWAY="+gatewayIP,
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
		return nil, fmt.Errorf("get home dir: %w", err)
	}
	agentHome := filepath.Join(home, ".membrane", "home")
	if err := os.MkdirAll(agentHome, 0755); err != nil {
		return nil, fmt.Errorf("create agent home dir: %w", err)
	}
	args = append(args, "-v", agentHome+":/home/agent")
	args = append(args, "-v", s.caVolume+":/membrane-ca:ro")
	args = append(args,
		// CA trust for runtimes that don't use the system store by default
		"-e", "NODE_EXTRA_CA_CERTS=/membrane-ca/ca.crt",
		"-e", "NODE_USE_SYSTEM_CA=1",
		"-e", "REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt",
		"-e", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		"-e", "CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt",
	)

	// Extra args from config.
	args = append(args, cfg.Args...)

	if title := os.Getenv("MEMBRANE_TITLE"); title != "" {
		args = append(args, "-e", "MEMBRANE_TITLE="+title)
	}

	// Image name.
	args = append(args, agentImageName)

	// Passthrough args (non-flag arguments to membrane binary).
	args = append(args, passthrough...)

	return args, nil
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
