package membrane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// CLIOverrides holds config values passed via CLI flags. List fields are
// appended to the merged file config; scalar fields replace it.
type CLIOverrides struct {
	Sealed      []string
	Readonly    []string
	Allow       []string // raw strings, parsed via ParseAllowEntry
	Args        []string
	DNSResolver string
}

// Run is the main entry point called from cmd/membrane/main.go.
// passthrough args are forwarded as the container command.
func Run(noUpdate bool, trace bool, noGlobalConfig bool, traceLog string, sessionIDFile string, passthrough []string, cli CLIOverrides) (retErr error) {

	if runtime.GOOS == "darwin" {
		os.Setenv("DOCKER_CONTEXT", "colima-membrane")
	}

	repoDir, err := ensureRepo()
	if err != nil {
		return err
	}

	if err := ensureDeps(repoDir); err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}
	membraneDir := filepath.Join(home, ".membrane")

	if !noUpdate {
		if err := checkAndUpdate(repoDir); err != nil {
			// Non-fatal: warn and continue.
			fmt.Fprintf(os.Stderr, "Warning: update check failed: %v\n", err)
		}
	}
	// Initialize from the available repository, preserving user edits on updates.
	if err := writeDefaultFiles(membraneDir); err != nil {
		return err
	}
	if err := ensureImages(repoDir); err != nil {
		return err
	}

	workspaceDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	workspaceDir, err = filepath.EvalSymlinks(workspaceDir)
	if err != nil {
		return fmt.Errorf("resolve workspace symlinks: %w", err)
	}

	cfg, err := loadConfig(workspaceDir, noGlobalConfig)
	if err != nil {
		return err
	}

	cfg.Sealed = append(cfg.Sealed, cli.Sealed...)
	cfg.Readonly = append(cfg.Readonly, cli.Readonly...)
	cfg.Args = append(cfg.Args, cli.Args...)
	for _, entry := range cli.Allow {
		rule, err := ParseAllowEntry(entry)
		if err != nil {
			return fmt.Errorf("invalid --allow value %q: %w", entry, err)
		}
		cfg.Allow = append(cfg.Allow, rule)
	}
	if cli.DNSResolver != "" {
		cfg.DNSResolver = cli.DNSResolver
	}

	mounts, err := resolveMounts(workspaceDir, cfg.Mounts)
	if err != nil {
		return err
	}
	policy, err := resolveFilesystemPolicy(workspaceDir, cfg, mounts)
	if err != nil {
		return err
	}

	s, err := newSession(membraneDir)
	if err != nil {
		return err
	}
	// Retained logs stay in the session; only its disposable files are removed.
	// Register before container teardown so mounted inputs outlive the workload.
	stagedRoot := filepath.Join(s.runtimeDir, "agent-root")
	defer func() {
		retErr = errors.Join(retErr, removePreparedAgentRoot(stagedRoot), os.RemoveAll(s.runtimeDir))
	}()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	if err := prepareAgentRoot(ctx, filepath.Join(membraneDir, "agent-root"), stagedRoot); err != nil {
		return err
	}
	s.directoryMounts = mounts
	s.policyRoots = make(map[int]string)
	for _, entry := range policy {
		s.policyRoots[entry.Root] = mounts[entry.Root].Path
	}

	if sessionIDFile != "" {
		if err := os.WriteFile(sessionIDFile, []byte(s.id), 0o644); err != nil {
			return fmt.Errorf("write session id file: %w", err)
		}
	}

	// Resolve trace log path before starting session (needed for bind mount).
	traceLogFile := traceLog
	if trace && traceLogFile == "" {
		traceLogFile = filepath.Join(s.logsDir, s.agentContainer+".jsonl.gz")
	}
	if trace && !filepath.IsAbs(traceLogFile) {
		traceLogFile, err = filepath.Abs(traceLogFile)
		if err != nil {
			return fmt.Errorf("resolve trace log path: %w", err)
		}
	}
	if err := checkBPFLSM(ctx); err != nil {
		return err
	}

	policyFile := ""
	if len(policy) != 0 {
		policyFile, err = writePolicyFile(s.runtimeDir, policy)
		if err != nil {
			return err
		}
		defer os.Remove(policyFile)
	}

	// Each instruction source comes from this invocation's independent template
	// copy. Only narrow readonly files are bound, never the template or runtime.
	instructions, err := os.ReadFile(filepath.Join(stagedRoot, "etc/membrane/AGENTS.md"))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read prepared Membrane instructions: %w", err)
	}
	for _, name := range []string{"etc/membrane/AGENTS.md", "etc/claude-code/CLAUDE.md"} {
		source := filepath.Join(stagedRoot, name)
		info, err := os.Stat(source)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("instruction source %s must be a regular file", source)
		}
		s.agentFileMounts = append(s.agentFileMounts, agentFileMount{source, "/" + name})
	}
	if !noGlobalConfig {
		globalPath, err := filepath.EvalSymlinks(filepath.Join(membraneDir, "config.yaml"))
		if err != nil {
			return fmt.Errorf("resolve global configuration: %w", err)
		}
		s.agentFileMounts = append(s.agentFileMounts, agentFileMount{globalPath, "/etc/membrane/config.yaml"})
	}
	if len(instructions) != 0 {
		codexDir := filepath.Join(stagedRoot, "home/agent/.codex")
		codexName, codexInstructions := "AGENTS.md", ""
		for _, name := range []string{"AGENTS.override.md", "AGENTS.md"} {
			data, err := os.ReadFile(filepath.Join(codexDir, name))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return fmt.Errorf("read prepared Codex %s: %w", name, err)
			}
			if name == "AGENTS.override.md" && strings.TrimSpace(string(data)) == "" {
				continue
			}
			codexName, codexInstructions = name, string(data)+"\n\n"
			break
		}
		f, err := os.CreateTemp(s.runtimeDir, "membrane-instructions-*.md")
		if err != nil {
			return fmt.Errorf("create Codex instruction copy: %w", err)
		}
		_, err = f.WriteString(codexInstructions + string(instructions))
		err = errors.Join(err, f.Chmod(0644), f.Close())
		if err != nil {
			return fmt.Errorf("write Codex instruction copy: %w", err)
		}
		s.agentFileMounts = append(s.agentFileMounts, agentFileMount{f.Name(), "/home/agent/.codex/" + codexName})
	}

	var setupSpinner *spinner
	if trace && term.IsTerminal(int(os.Stdin.Fd())) {
		setupSpinner = newSpinner()
		setupSpinner.Start("Setting up sandbox...")
	}
	cleanup, gatewayIP, err := startSession(ctx, &s, cfg, trace, traceLogFile, policyFile)
	if setupSpinner != nil {
		setupSpinner.Stop()
	}
	defer func() {
		var teardownSpinner *spinner
		if trace && term.IsTerminal(int(os.Stdin.Fd())) {
			teardownSpinner = newSpinner()
			teardownSpinner.Start("Tearing down sandbox...")
		}
		retErr = errors.Join(retErr, cleanup())
		if teardownSpinner != nil {
			teardownSpinner.Stop()
		}
	}()
	if err != nil {
		return fmt.Errorf("start session: %w", err)
	}

	args, err := buildAgentArgs(workspaceDir, cfg, passthrough, s, gatewayIP, hasSysbox())
	if err != nil {
		return err
	}

	return runAgent(ctx, s, args)
}

func checkAndUpdate(repoDir string) error {
	// Skip update if not on main (e.g. src is a symlink to a dev working dir).
	branchOut, err := exec.Command("git", "-C", repoDir, "rev-parse", "--abbrev-ref", "HEAD").Output()
	if err != nil || strings.TrimSpace(string(branchOut)) != "main" {
		return nil
	}

	remote, err := remoteCommit()
	if err != nil {
		return err
	}

	localOut, err := exec.Command("git", "-C", repoDir, "rev-parse", "HEAD").Output()
	if err != nil {
		return fmt.Errorf("get local commit: %w", err)
	}
	local := strings.TrimSpace(string(localOut))

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

	return buildImages(repoDir)
}
