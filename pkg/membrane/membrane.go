package membrane

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// CLIOverrides holds config values passed via CLI flags. List fields are
// appended to the merged file config; scalar fields replace it.
type CLIOverrides struct {
	Ignore    []string
	Readonly  []string
	Hostnames []string
	Cidrs     []string
	Args      []string
	Resolver  string
}

// Run is the main entry point called from cmd/membrane/main.go.
// passthrough args are forwarded as the container command.
func Run(noUpdate bool, trace bool, traceLog string, passthrough []string, cli CLIOverrides) error {
	repoDir, err := ensureRepo()
	if err != nil {
		return err
	}

	// Write default config if it doesn't exist yet. Safe to call every run.
	// Must run after ensureRepo — reads config-default.yaml from the cloned repo.
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}
	membraneDir := filepath.Join(home, ".membrane")
	if err := writeDefaultConfig(membraneDir); err != nil {
		return err
	}

	if !noUpdate {
		if err := checkAndUpdate(repoDir); err != nil {
			// Non-fatal: warn and continue.
			fmt.Fprintf(os.Stderr, "Warning: update check failed: %v\n", err)
		}
	}

	if err := ensureImage(repoDir); err != nil {
		return err
	}

	workspaceDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	cfg, err := loadConfig(workspaceDir)
	if err != nil {
		return err
	}

	cfg.Ignore = append(cfg.Ignore, cli.Ignore...)
	cfg.Readonly = append(cfg.Readonly, cli.Readonly...)
	cfg.Hostnames = append(cfg.Hostnames, cli.Hostnames...)
	cfg.Cidrs = append(cfg.Cidrs, cli.Cidrs...)
	cfg.Args = append(cfg.Args, cli.Args...)
	if cli.Resolver != "" {
		cfg.Resolver = cli.Resolver
	}

	m, err := scan(workspaceDir, cfg)
	if err != nil {
		return err
	}

	args, containerName, err := buildArgs(workspaceDir, m, cfg, passthrough)
	if err != nil {
		return err
	}

	if !trace {
		return execDocker(args)
	}

	// -- Traced run: Tracee sidecar → agent container → cleanup --

	// Resolve trace log path.
	traceLogFile := traceLog
	if traceLogFile == "" {
		traceLogFile = filepath.Join(membraneDir, "trace", containerName+".jsonl.gz")
	}
	if err := os.MkdirAll(filepath.Dir(traceLogFile), 0o755); err != nil {
		return fmt.Errorf("create trace dir: %w", err)
	}

	tracer := NewTracer(containerName, traceLogFile)
	if err := tracer.Start(); err != nil {
		return fmt.Errorf("tracee failed to start: %w\nRe-run with --no-trace to start without tracing", err)
	}
	defer tracer.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		<-sigs
		cancel()
	}()

	// Run the agent container in a goroutine so we can resolve its
	// container ID and set up event filtering while it runs.
	agentErr := make(chan error, 1)
	go func() { agentErr <- execDocker(args) }()

	// Retry docker inspect until the container exists (up to ~5s).
	var cid string
	for i := 0; i < 10; i++ {
		out, err := exec.Command("docker", "inspect", "-f", "{{.Id}}", containerName).Output()
		if err == nil {
			cid = strings.TrimSpace(string(out))
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if cid == "" {
		return fmt.Errorf("could not resolve container ID for %s", containerName)
	}

	tracer.StartStreaming(cid)

	// Wait for the agent container to exit or a signal to arrive.
	var result error
	select {
	case result = <-agentErr:
	case <-ctx.Done():
		// Signal received; stop the agent container so execDocker unblocks
		// and restores the terminal. Tracee cleaned up by deferred tracer.Stop().
		fmt.Fprintln(os.Stderr, "\r\nmembrane: stopping...")
		_ = exec.Command("docker", "stop", "-t", "2", containerName).Run()
		<-agentErr
	}
	return result
}

func checkAndUpdate(repoDir string) error {
	remote, err := remoteCommit()
	if err != nil {
		return err
	}

	local, err := localCommit(repoDir)
	if err != nil {
		return err
	}

	if remote == local {
		return nil
	}

	dirty, err := isDirty(repoDir)
	if err != nil {
		return err
	}
	if dirty {
		if err := backupSrc(repoDir); err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stderr, "Updating to %s...\n", remote[:7])
	if err := update(repoDir); err != nil {
		return err
	}

	return buildImage(repoDir)
}
