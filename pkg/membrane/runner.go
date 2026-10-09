package membrane

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty/v2"
	"golang.org/x/term"
)

// writeNetworkRulesFile serialises allow and deny rules to a temp file and returns its path.
// The caller is responsible for removing the file when done.
func writeNetworkRulesFile(allow, deny []NetworkRule) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	dir := filepath.Join(home, ".membrane", "tmp")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create tmp dir: %w", err)
	}
	f, err := os.CreateTemp(dir, "membrane-network-rules-*.json")
	if err != nil {
		return "", fmt.Errorf("create network rules file: %w", err)
	}
	defer f.Close()
	if allow == nil {
		allow = []NetworkRule{}
	}
	if deny == nil {
		deny = []NetworkRule{}
	}
	if err := json.NewEncoder(f).Encode(map[string][]NetworkRule{"allow": allow, "deny": deny}); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("write network rules file: %w", err)
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
	cgroupParent     string
	handlerContainer string
	internalNetwork  string
	externalNetwork  string
	caVolume         string

	agentFileMounts []string
	directoryMounts []directoryMount
	policyRoots     map[int]string
}

// --mount refuses missing bind sources, unlike -v which can create them. CSV
// encoding preserves source and destination paths as individual fields.
func directoryBind(source, destination string, readonly bool) string {
	fields := []string{"type=bind", "src=" + source, "dst=" + destination}
	if readonly {
		fields = append(fields, "readonly")
	}
	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write(fields)
	w.Flush()
	return strings.TrimSuffix(b.String(), "\n")
}

// createSessionCgroup establishes the scope before any container workload can
// run. The handler receives only this workload subtree for scoping and kill.
func createSessionCgroup(ctx context.Context, s *sessionNames) (func() error, error) {
	cleanup := func() error { return nil }
	out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.CgroupVersion}} {{.CgroupDriver}}").Output()
	if err != nil {
		return cleanup, fmt.Errorf("inspect Docker cgroups: %w", err)
	}
	layout := strings.Fields(string(out))
	if len(layout) != 2 {
		return cleanup, fmt.Errorf("unexpected Docker cgroup configuration: %q", out)
	}
	var parent string
	var create, remove []string
	switch layout[0] + " " + layout[1] {
	case "2 cgroupfs":
		parent = "/membrane-" + s.id
		path := "/sys/fs/cgroup" + parent
		create, remove = []string{"mkdir", path}, []string{"rmdir", path}
	case "2 systemd":
		// A systemd slice without hyphens is at the root.
		parent = "membrane" + s.id + ".slice"
		create, remove = []string{"systemctl", "start", parent}, []string{"systemctl", "stop", parent}
	default:
		return cleanup, fmt.Errorf("Membrane requires cgroup v2 with cgroupfs or systemd; Docker reports %q", layout[0]+" "+layout[1])
	}
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "membrane: requesting sudo to manage workload cgroups")
	}
	s.cgroupParent = parent
	cleanup = func() error {
		if out, err := dockerHostCommand(context.Background(), remove...).CombinedOutput(); err != nil {
			return fmt.Errorf("remove session cgroup %s: %s: %w", s.cgroupParent, out, err)
		}
		return nil
	}
	if out, err := dockerHostCommand(ctx, create...).CombinedOutput(); err != nil {
		if ctx.Err() == nil {
			// A failed mkdir may mean the path already belongs to someone else.
			cleanup = func() error { return nil }
		}
		return cleanup, fmt.Errorf("pre-create session cgroup (requires host permission for %s): %s: %w", strings.Join(create, " "), out, err)
	}
	return cleanup, nil
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
func startSession(ctx context.Context, s *sessionNames, cfg *config, trace bool, traceLogFile, policyFile string) (func() error, string, error) {
	cleanupCgroup, cgroupErr := createSessionCgroup(ctx, s)
	cleanup := func() error {
		// Remove all workload processes before detaching BPF, including DinD.
		_ = exec.Command("docker", "rm", "-f", s.agentContainer).Run()
		if err := stopWorkload(*s); err != nil {
			return err
		}
		// Prevent a created container from starting after enforcement is released.
		out, err := exec.Command("docker", "container", "ls", "-aq", "--filter", "name=^/"+s.agentContainer+"$").CombinedOutput()
		if err != nil || len(strings.TrimSpace(string(out))) != 0 {
			return fmt.Errorf("cannot confirm agent removal: %s (%v)", out, err)
		}
		_ = exec.Command("docker", "stop", "-t", "10", s.handlerContainer).Run()
		_ = exec.Command("docker", "rm", s.handlerContainer).Run()
		cgroupErr := cleanupCgroup()
		_ = exec.Command("docker", "network", "rm", s.internalNetwork).Run()
		_ = exec.Command("docker", "network", "rm", s.externalNetwork).Run()
		_ = exec.Command("docker", "volume", "rm", s.caVolume).Run()
		return cgroupErr
	}

	if cgroupErr != nil {
		return cleanupCgroup, "", cgroupErr
	}

	if out, err := exec.CommandContext(ctx, "docker", "volume", "create",
		s.caVolume).CombinedOutput(); err != nil {
		return cleanup, "", fmt.Errorf("create ca volume %s: %s: %w",
			s.caVolume, out, err)
	}

	if out, err := exec.CommandContext(ctx, "docker", "network", "create",
		s.externalNetwork).CombinedOutput(); err != nil {
		return cleanup, "", fmt.Errorf("create network %s: %s: %w",
			s.externalNetwork, out, err)
	}

	out, err := exec.CommandContext(ctx, "docker", "network", "create",
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
	cleanup = func() error {
		err := origCleanup()
		removeDockerUserRule(bridge)
		return err
	}

	networkRulesFile, err := writeNetworkRulesFile(cfg.Allow, cfg.Deny)
	if err != nil {
		return cleanup, "", fmt.Errorf("write network rules file: %w", err)
	}
	prevCleanup := cleanup
	cleanup = func() error {
		err := prevCleanup()
		os.Remove(networkRulesFile)
		return err
	}

	handlerArgs := []string{
		"run", "-d",
		"--name", s.handlerContainer,
		"--cgroupns=private",
		"--network", s.externalNetwork,
		"--cap-add=NET_ADMIN",
		"--sysctl", "net.ipv4.ip_forward=1",
		"-v", s.caVolume + ":/membrane-ca",
		"-v", networkRulesFile + ":/etc/membrane/network-rules.json:ro",
		"-e", "MEMBRANE_DNS_RESOLVER=" + cfg.dnsResolver(),
		"-e", fmt.Sprintf("MEMBRANE_SSL_INSECURE=%v", cfg.SSLInsecure),
	}

	handlerArgs = append(handlerArgs,
		"--mount", "type=bind,src="+sessionCgroupPath(*s)+",dst=/workload-cgroup",
		"-e", "MEMBRANE_TARGET_CGROUP=/workload-cgroup")
	if trace || policyFile != "" {
		handlerArgs = append(handlerArgs, "--cap-add=BPF", "--cap-add=PERFMON")
	}
	if trace {
		traceDir := filepath.Dir(traceLogFile)
		if err := os.MkdirAll(traceDir, 0755); err != nil {
			return cleanup, "", err
		}
		handlerArgs = append(handlerArgs,
			"-v", "/sys/kernel/tracing:/sys/kernel/tracing:ro",
			"-e", "MEMBRANE_TRACE_FILE=/trace/"+filepath.Base(traceLogFile),
			"-v", traceDir+":/trace")
	}
	if policyFile != "" {
		roots := make([]int, 0, len(s.policyRoots))
		for root := range s.policyRoots {
			roots = append(roots, root)
		}
		sort.Ints(roots)
		for _, root := range roots {
			handlerArgs = append(handlerArgs, "--mount", directoryBind(s.policyRoots[root], "/policy-roots/"+strconv.Itoa(root), true))
		}
		handlerArgs = append(handlerArgs,
			"-v", policyFile+":/etc/membrane/policy.json:ro",
			"-e", "MEMBRANE_POLICY_FILE=/etc/membrane/policy.json",
			"-e", "MEMBRANE_POLICY_ROOTS=/policy-roots")
	}

	handlerArgs = append(handlerArgs, handlerImageName)

	if out, err := exec.CommandContext(ctx, "docker", handlerArgs...).CombinedOutput(); err != nil {
		return cleanup, "", fmt.Errorf("start handler: %s: %w", out, err)
	}

	if out, err := exec.CommandContext(ctx, "docker", "network", "connect",
		s.internalNetwork, s.handlerContainer).CombinedOutput(); err != nil {
		return cleanup, "", fmt.Errorf("connect handler to internal network: %s: %w", out, err)
	}

	// Wait for handler ready signal (timeout 30s).
	for i := 0; i < 30; i++ {
		if err := ctx.Err(); err != nil {
			return cleanup, "", err
		}
		if exec.CommandContext(ctx, "docker", "exec", s.handlerContainer,
			"test", "-f", "/tmp/handler-ready").Run() == nil {
			break
		}
		running, _ := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Running}}", s.handlerContainer).Output()
		if i == 29 || strings.TrimSpace(string(running)) != "true" {
			logs, _ := exec.CommandContext(ctx, "docker", "logs",
				s.handlerContainer).CombinedOutput()
			return cleanup, "", fmt.Errorf(
				"handler exited or did not become ready within 30s\nHandler logs:\n%s", logs)
		}
		time.Sleep(time.Second)
	}

	// Keep handler logs readable during the session; gzip them on cleanup.
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
	cleanup = func() error {
		err := prevCleanup2()
		_ = logCmd.Process.Kill()
		_ = logCmd.Wait()
		logFile.Close()
		if err := gzipFile(logPath + ".gz"); err == nil {
			os.Remove(logPath)
		}
		return err
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

// buildAgentArgs constructs docker create for a scoped workload.
// passthrough args are appended after the image name as the container command.
func buildAgentArgs(workspaceDir string, cfg *config, passthrough []string, s sessionNames, gatewayIP string, sysbox bool) ([]string, error) {
	if s.cgroupParent == "" {
		return nil, errors.New("workload requires a pre-created session cgroup")
	}
	args := []string{"create", "-it", "--rm", "--init", "--name", s.agentContainer}

	if sysbox {
		args = append(args, "--runtime=sysbox-runc", "-e", "MEMBRANE_DIND=1")
	}

	args = append(args,
		"--cap-add=NET_ADMIN",
		"--cap-add=CAP_SETPCAP",
		"--network", s.internalNetwork,
		"-e", "MEMBRANE_GATEWAY="+gatewayIP,
		"--workdir", workspaceDir,
	)
	for _, mount := range s.directoryMounts {
		// Docker honors mount modes; eBPF independently enforces the
		// filesystem policy, including through writable aliases.
		args = append(args, "--mount", directoryBind(mount.Path, mount.Path, mount.Mode == "ro"))
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

	args = append(args, s.agentFileMounts...)
	// Extra args from config.
	args = append(args, cfg.Args...)
	// Session identity takes precedence over a configured Docker parent.
	args = append(args, "--cgroup-parent="+s.cgroupParent)

	if title := os.Getenv("MEMBRANE_TITLE"); title != "" {
		args = append(args, "-e", "MEMBRANE_TITLE="+title)
	}

	// Image name.
	args = append(args, agentImageName)

	// Passthrough args (non-flag arguments to membrane binary).
	args = append(args, passthrough...)

	return args, nil
}

// gzipFile compresses a closed handler log, independently of eBPF trace output.
func gzipFile(dst string) error {
	in, err := os.Open(strings.TrimSuffix(dst, ".gz"))
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	defer gz.Close()
	_, err = io.Copy(gz, in)
	return err
}

// runAgent keeps the existing terminal proxy for start/attach and stops the
// workload if its handler exits. Creation never executes image code.
func runAgent(ctx context.Context, s sessionNames, args []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if args[0] == "create" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			for i, arg := range args {
				if arg == "-it" {
					args[i] = "-i"
				}
			}
		}
		if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("create agent: %s: %w", out, err)
		}
		args = []string{"start", "--attach", "--interactive", s.agentContainer}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Cancellation is handled by the select below. Canceling docker wait at
	// the same time would incorrectly report an intentional stop as failure.
	waitCtx, cancel := context.WithCancel(context.Background())
	handlerDone := make(chan error, 1)
	waitFinished := make(chan struct{})
	defer func() {
		cancel()
		<-waitFinished
	}()
	go func() {
		defer close(waitFinished)
		out, err := exec.CommandContext(waitCtx, "docker", "wait", s.handlerContainer).CombinedOutput()
		handlerDone <- fmt.Errorf("handler exited during session: %s (%v)", strings.TrimSpace(string(out)), err)
	}()
	agentDone := make(chan error, 1)
	go func() { agentDone <- execDocker(args) }()
	select {
	case err := <-agentDone:
		running, inspectErr := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", s.handlerContainer).Output()
		if inspectErr != nil || strings.TrimSpace(string(running)) != "true" {
			logs, _ := exec.Command("docker", "logs", s.handlerContainer).CombinedOutput()
			return fmt.Errorf("handler failed during session\nHandler logs:\n%s", logs)
		}
		return err
	case err := <-handlerDone:
		_ = exec.Command("docker", "rm", "-f", s.agentContainer).Run()
		err = errors.Join(err, stopWorkload(s))
		select {
		case <-agentDone:
		case <-time.After(30 * time.Second):
			return fmt.Errorf("%w; timed out waiting for workload attachment to exit", err)
		}
		logs, _ := exec.Command("docker", "logs", s.handlerContainer).CombinedOutput()
		return fmt.Errorf("%w\nHandler logs:\n%s", err, logs)
	case <-ctx.Done():
		_ = exec.Command("docker", "stop", "-t", "2", s.agentContainer).Run()
		err := <-agentDone
		if err != nil {
			return err
		}
		return ctx.Err()
	}
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
	done := make(chan struct{})
	defer close(done)
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
			for {
				select {
				case sig := <-sigCh:
					_ = cmd.Process.Signal(sig)
				case <-done:
					return
				}
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
		for {
			select {
			case <-resizeCh:
				if ws, err := pty.GetsizeFull(os.Stdin); err == nil {
					_ = pty.Setsize(ptmx, ws)
				}
			case <-done:
				return
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
		for {
			select {
			case sig := <-sigCh:
				_ = cmd.Process.Signal(sig)
			case <-done:
				return
			}
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
