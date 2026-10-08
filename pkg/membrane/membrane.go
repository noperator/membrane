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

	policy, err := resolveFilesystemPolicy(workspaceDir, cfg)
	if err != nil {
		return err
	}

	s := newSessionNames()

	if sessionIDFile != "" {
		if err := os.WriteFile(sessionIDFile, []byte(s.id), 0o644); err != nil {
			return fmt.Errorf("write session id file: %w", err)
		}
	}

	// Resolve trace log path before starting session (needed for bind mount).
	traceLogFile := traceLog
	if trace && traceLogFile == "" {
		traceLogFile = filepath.Join(membraneDir, "trace", s.agentContainer+".jsonl.gz")
	}
	if trace && !filepath.IsAbs(traceLogFile) {
		traceLogFile, err = filepath.Abs(traceLogFile)
		if err != nil {
			return fmt.Errorf("resolve trace log path: %w", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	if err := checkBPFLSM(ctx); err != nil {
		return err
	}

	policyFile := ""
	if len(policy) != 0 {
		policyFile, err = writePolicyFile(policy)
		if err != nil {
			return err
		}
		defer os.Remove(policyFile)
	}

	instructionsPath, err := filepath.EvalSymlinks(filepath.Join(membraneDir, "AGENTS.md"))
	if err != nil {
		return fmt.Errorf("resolve user instructions: %w", err)
	}
	instructions, err := os.ReadFile(instructionsPath)
	if err != nil {
		return fmt.Errorf("read user instructions: %w", err)
	}
	s.agentFileMounts = append(s.agentFileMounts,
		"-v", instructionsPath+":/etc/membrane/AGENTS.md:ro",
		"-v", instructionsPath+":/etc/claude-code/CLAUDE.md:ro")
	if !noGlobalConfig {
		globalPath, err := filepath.EvalSymlinks(filepath.Join(membraneDir, "config.yaml"))
		if err != nil {
			return fmt.Errorf("resolve global configuration: %w", err)
		}
		s.agentFileMounts = append(s.agentFileMounts, "-v", globalPath+":/etc/membrane/config.yaml:ro")
	}
	// Append user-managed guidance to the active Codex global file, keeping the
	// shared originals intact. Create parents as the host user, rather than Docker.
	codexDir := filepath.Join(membraneDir, "home", ".codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		return fmt.Errorf("create Codex directory: %w", err)
	}
	codexName, codexInstructions := "AGENTS.md", ""
	for _, name := range []string{"AGENTS.override.md", "AGENTS.md"} {
		data, err := os.ReadFile(filepath.Join(codexDir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read Codex %s: %w", name, err)
		}
		if name == "AGENTS.override.md" && strings.TrimSpace(string(data)) == "" {
			continue
		}
		codexName, codexInstructions = name, string(data)+"\n\n"
		break
	}
	tmpDir := filepath.Join(membraneDir, "tmp")
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return fmt.Errorf("create session tmp dir: %w", err)
	}
	f, err := os.CreateTemp(tmpDir, "membrane-instructions-*.md")
	if err != nil {
		return fmt.Errorf("create Codex instruction copy: %w", err)
	}
	defer os.Remove(f.Name()) // Registered before workload teardown.
	_, err = f.WriteString(codexInstructions + string(instructions))
	if err == nil {
		err = f.Chmod(0644)
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write Codex instruction copy: %w", err)
	}
	s.agentFileMounts = append(s.agentFileMounts, "-v", f.Name()+":/home/agent/.codex/"+codexName+":ro")

	var setupSpinner *spinner
	if trace && term.IsTerminal(int(os.Stdin.Fd())) {
		setupSpinner = newSpinner()
		setupSpinner.Start("Setting up sandbox...")
	}
	cleanup, gatewayIP, err := startSession(ctx, &s, cfg, trace, traceLogFile, workspaceDir, policyFile)
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
