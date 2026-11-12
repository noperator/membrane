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
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty/v2"
	"golang.org/x/term"
)

// writeNetworkRulesFile serialises allow and deny rules to a temp file and returns its path.
// The caller is responsible for removing the file when done.
func writeNetworkRulesFile(dir string, allow, deny []NetworkRule) (string, error) {
	f, err := os.CreateTemp(dir, "membrane-network-rules-*.json")
	if err != nil {
		return "", fmt.Errorf("create network rules file: %w", err)
	}
	if allow == nil {
		allow = []NetworkRule{}
	}
	if deny == nil {
		deny = []NetworkRule{}
	}
	err = json.NewEncoder(f).Encode(map[string][]NetworkRule{"allow": allow, "deny": deny})
	err = errors.Join(err, f.Close())
	if err != nil {
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
	dir              string
	logsDir          string
	runtimeDir       string

	agentFileMounts []agentFileMount
	directoryMounts []directoryMount
	policyRoots     map[int]string
	archivePaths    []string
}

type agentFileMount struct{ source, destination string }

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

func newSession(membraneDir string) (sessionNames, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return sessionNames{}, fmt.Errorf("generate session ID: %w", err)
	}
	id := hex.EncodeToString(b[:])
	s := sessionNames{
		id:               id,
		agentContainer:   "membrane-agent-" + id,
		handlerContainer: "membrane-handler-" + id,
		internalNetwork:  "membrane-internal-" + id,
		externalNetwork:  "membrane-external-" + id,
		caVolume:         "membrane-ca-" + id,
	}
	parent := filepath.Join(membraneDir, "sessions")
	if err := os.MkdirAll(parent, 0700); err != nil {
		return s, fmt.Errorf("create sessions directory: %w", err)
	}
	s.dir = filepath.Join(parent, id)
	s.logsDir = filepath.Join(s.dir, "logs")
	s.runtimeDir = filepath.Join(s.dir, "runtime")
	// Exclusive creation establishes ownership: never reuse an existing session.
	if err := os.Mkdir(s.dir, 0700); err != nil {
		return s, fmt.Errorf("create session directory: %w", err)
	}
	for _, dir := range []string{s.logsDir, s.runtimeDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			return s, fmt.Errorf("create session subdirectory: %w", err)
		}
	}
	return s, nil
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
func startSession(ctx context.Context, s *sessionNames, cfg *config, trace bool, traceLogFile, policyFile string) (cleanup func() error, gatewayIP string, retErr error) {
	// Teardown owns processes, mounts and an open log. Repeated calls return the
	// original result without acting on released resources or recompressing logs.
	defer func() { cleanup = sync.OnceValue(cleanup) }()
	cleanupCgroup, cgroupErr := createSessionCgroup(ctx, s)
	cleanup = func() error {
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

	networkRulesFile, err := writeNetworkRulesFile(s.runtimeDir, cfg.Allow, cfg.Deny)
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
		if err := os.MkdirAll(traceDir, 0700); err != nil {
			return cleanup, "", err
		}
		// Create as the host user so the handler can write private diagnostics
		// without leaving a root-owned 0600 file unreadable on native Linux.
		f, err := os.OpenFile(traceLogFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return cleanup, "", fmt.Errorf("create trace file: %w", err)
		}
		err = errors.Join(f.Chmod(0600), f.Close())
		if err != nil {
			return cleanup, "", fmt.Errorf("prepare trace file: %w", err)
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

	// Keep handler logs readable during the session; gzip them on cleanup.
	logPath := filepath.Join(s.logsDir, s.handlerContainer+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
		logErr := logFile.Close()
		if logErr == nil {
			logErr = gzipFile(logPath + ".gz")
		}
		if logErr == nil {
			logErr = os.Remove(logPath)
		}
		if logErr != nil {
			err = errors.Join(err, fmt.Errorf("retain handler log %s: %w", logPath, logErr))
		}
		return err
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

	out, err = exec.Command("docker", "inspect", "-f",
		fmt.Sprintf("{{(index .NetworkSettings.Networks %q).IPAddress}}",
			s.internalNetwork),
		s.handlerContainer).Output()
	if err != nil {
		return cleanup, "", fmt.Errorf("inspect handler IP: %w", err)
	}
	gatewayIP = strings.TrimSpace(string(out))
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
	args := []string{"create", "-it", "--init", "--name", s.agentContainer}

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

	args = append(args, "-v", s.caVolume+":/membrane-ca:ro")
	args = append(args,
		// CA trust for runtimes that don't use the system store by default
		"-e", "NODE_EXTRA_CA_CERTS=/membrane-ca/ca.crt",
		"-e", "NODE_USE_SYSTEM_CA=1",
		"-e", "REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt",
		"-e", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		"-e", "CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt",
	)

	// Explicit live mounts also mask generated instruction/config files. Docker
	// otherwise mounts our more-specific file through a user-mounted parent.
	var destinations []string
	for _, mount := range s.directoryMounts {
		destinations = append(destinations, mount.Path)
	}
	for i := 0; i < len(cfg.Args); i++ {
		arg, value, kind := cfg.Args[i], "", ""
		for _, flag := range []string{"--mount", "--volume", "--volumes-from", "--tmpfs", "-v"} {
			if arg == flag {
				if i+1 == len(cfg.Args) {
					return nil, fmt.Errorf("%s requires a mount value", flag)
				}
				i++
				kind, value = flag, cfg.Args[i]
				break
			}
			if strings.HasPrefix(arg, flag+"=") {
				kind, value = flag, strings.TrimPrefix(arg, flag+"=")
				break
			}
		}
		if kind == "" && strings.HasPrefix(arg, "-v") && len(arg) > 2 {
			kind, value = "-v", arg[2:]
		}
		if kind == "--volumes-from" {
			container, _, _ := strings.Cut(value, ":")
			out, err := exec.Command("docker", "inspect", "-f", "{{json .Mounts}}", container).Output()
			if err != nil {
				return nil, fmt.Errorf("inspect inherited mounts from %s: %w", container, err)
			}
			var mounts []struct{ Destination string }
			if err := json.Unmarshal(out, &mounts); err != nil {
				return nil, fmt.Errorf("decode inherited mounts from %s: %w", container, err)
			}
			for _, mount := range mounts {
				destinations = append(destinations, filepath.Clean(mount.Destination))
			}
		} else if kind == "--mount" {
			fields, err := csv.NewReader(strings.NewReader(value)).Read()
			if err != nil {
				return nil, fmt.Errorf("parse --mount: %w", err)
			}
			for _, field := range fields {
				key, val, _ := strings.Cut(field, "=")
				if key = strings.ToLower(key); key == "dst" || key == "destination" || key == "target" {
					destinations = append(destinations, filepath.Clean(val))
				}
			}
		} else if kind != "" {
			fields := strings.Split(value, ":")
			destination := fields[0]
			if kind != "--tmpfs" && len(fields) > 1 {
				destination = fields[1]
			}
			destinations = append(destinations, filepath.Clean(destination))
		}
	}
files:
	for _, file := range s.agentFileMounts {
		for _, destination := range destinations {
			if file.destination == destination || strings.HasPrefix(file.destination, strings.TrimSuffix(destination, "/")+"/") {
				continue files
			}
		}
		args = append(args, "--mount", directoryBind(file.source, file.destination, true))
	}
	// Extra args from config.
	args = append(args, cfg.Args...)
	// Session identity takes precedence over a configured Docker parent.
	args = append(args, "--cgroup-parent="+s.cgroupParent, "--rm=false")

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
func gzipFile(dst string) (retErr error) {
	in, err := os.Open(strings.TrimSuffix(dst, ".gz"))
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, in.Close()) }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, out.Close()) }()
	gz := gzip.NewWriter(out)
	defer func() { retErr = errors.Join(retErr, gz.Close()) }()
	_, err = io.Copy(gz, in)
	return err
}

// runAgent keeps the existing terminal proxy for start/attach and stops the
// workload if its handler exits. Creation never executes image code.
func runAgent(ctx context.Context, s sessionNames, args []string) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Watch required services throughout preparation, which can take longer
	// than container creation. A failed handler must cancel copy-in too.
	setupCtx, cancelSetup := context.WithCancel(ctx)
	defer cancelSetup()
	waitCtx, cancel := context.WithCancel(context.Background())
	handlerDone := make(chan error, 1)
	waitFinished := make(chan struct{})
	var handlerErr error
	defer func() {
		cancel()
		<-waitFinished
		if handlerErr == nil {
			select {
			case handlerErr = <-handlerDone:
			default:
			}
		}
		if handlerErr != nil {
			logs, _ := exec.Command("docker", "logs", s.handlerContainer).CombinedOutput()
			handlerErr = fmt.Errorf("%w\nHandler logs:\n%s", handlerErr, logs)
			// ExitError keeps the workload status at the CLI. Report the service
			// failure separately so that a concurrent exit cannot hide its cause.
			fmt.Fprintf(os.Stderr, "membrane: %v\n", handlerErr)
			retErr = errors.Join(retErr, handlerErr)
		}
	}()
	go func() {
		defer close(waitFinished)
		out, err := exec.CommandContext(waitCtx, "docker", "wait", s.handlerContainer).CombinedOutput()
		if waitCtx.Err() == nil {
			handlerDone <- fmt.Errorf("handler exited during session: %s (%v)", strings.TrimSpace(string(out)), err)
			cancelSetup()
		}
	}()
	var archiveExclusions []string
	if args[0] == "create" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			for i, arg := range args {
				if arg == "-it" {
					args[i] = "-i"
				}
			}
		}
		if out, err := exec.CommandContext(setupCtx, "docker", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("create agent: %s: %w", out, err)
		}
		// The bundled agent starts as UID/GID 1000. Its entrypoint then adjusts
		// only private home objects to the workspace's container-side identity.
		var err error
		archiveExclusions, err = copyAgentRoot(setupCtx, filepath.Join(s.runtimeDir, "agent-root"), s.agentContainer, 1000, 1000)
		if err != nil {
			return fmt.Errorf("prepare agent filesystem: %w", err)
		}
		args = []string{"start", "--attach", "--interactive", s.agentContainer}
	}
	if err := setupCtx.Err(); err != nil {
		return err
	}
	if len(s.archivePaths) != 0 {
		defer func() {
			// An earlier workload cancellation must not cancel orderly collection;
			// another signal abandons the export and lets owned cleanup continue.
			archiveCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
			defer stop()
			if err := archiveAgent(archiveCtx, s, archiveExclusions); err != nil {
				// The CLI preserves ExitError's status. Report collection separately
				// so that doing so cannot hide a second failure.
				fmt.Fprintf(os.Stderr, "membrane: archive failed: %v\n", err)
				retErr = errors.Join(retErr, fmt.Errorf("archive agent files: %w", err))
			}
		}()
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- execDocker(args) }()
	select {
	case err := <-agentDone:
		running, inspectErr := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", s.handlerContainer).Output()
		if inspectErr != nil || strings.TrimSpace(string(running)) != "true" {
			handlerErr = errors.New("handler failed during session")
		}
		return err
	case err := <-handlerDone:
		handlerErr = err
		_ = exec.Command("docker", "kill", s.agentContainer).Run()
		err = stopWorkload(s)
		select {
		case agentErr := <-agentDone:
			return errors.Join(agentErr, err)
		case <-time.After(30 * time.Second):
			return errors.Join(err, errors.New("timed out waiting for workload attachment to exit"))
		}
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
