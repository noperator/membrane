package membrane

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ensureDeps checks that all required dependencies are installed,
// configured, and running. Runs at startup after ensureRepo.
func ensureDeps(repoDir string) error {
	if runtime.GOOS == "darwin" {
		return ensureDepsDarwin(repoDir)
	}
	return ensureDepsLinux(repoDir)
}

// ensureDepsDarwin checks macOS-specific deps: colima, docker CLI,
// membrane Colima profile configured, and Colima running.
func ensureDepsDarwin(repoDir string) error {
	// Phase 1: Installation
	if err := checkBinary("colima", "scripts/install-macos.sh", repoDir); err != nil {
		return err
	}
	if err := checkBinary("docker", "scripts/install-macos.sh", repoDir); err != nil {
		return err
	}

	// Phase 2: Configuration — profile exists (safe without daemon)
	out, err := exec.Command("colima", "list", "-j").Output()
	profileFound := false
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			var profile struct {
				Name string `json:"name"`
			}
			if json.Unmarshal([]byte(line), &profile) == nil && profile.Name == "membrane" {
				profileFound = true
				break
			}
		}
	}
	if !profileFound {
		return offerInstall(
			"Colima 'membrane' profile not found.",
			"scripts/install-macos.sh",
			repoDir,
		)
	}

	// Phase 3: Running — must be up before we can check sysbox
	if err := exec.Command("colima", "status", "--profile", "membrane").Run(); err != nil {
		if err := offerStart(
			"Colima 'membrane' profile is not running.",
			func() error {
				return exec.Command("colima", "start",
					"--profile", "membrane",
					"--activate=false",
				).Run()
			},
		); err != nil {
			return err
		}
	}

	// Phase 4: Configuration — sysbox registered (safe now, Colima is up)
	if err := checkSysbox(); err != nil {
		return offerInstall(
			err.Error(),
			"scripts/install-macos.sh",
			repoDir,
		)
	}

	return nil
}

// ensureDepsLinux checks Linux-specific deps: docker CLI,
// sysbox configured, and Docker daemon running.
func ensureDepsLinux(repoDir string) error {
	// Phase 1: Installation
	if err := checkBinary("docker", "scripts/install-linux.sh", repoDir); err != nil {
		return err
	}

	// Phase 2: Running — inspect runtime registration only after Docker is up.
	if err := exec.Command("docker", "info").Run(); err != nil {
		if err := offerStart(
			"Docker is not running.",
			func() error {
				return exec.Command("sudo", "systemctl", "start", "docker").Run()
			},
		); err != nil {
			return err
		}
	}

	// Phase 3: Configuration and backing services
	if err := checkSysbox(); err != nil {
		return offerInstall(err.Error(), "scripts/install-linux.sh", repoDir)
	}

	return nil
}

// checkBinary checks if a binary is in PATH. If not, offers to run
// the install script.
func checkBinary(name, installScript, repoDir string) error {
	if _, err := exec.LookPath(name); err != nil {
		return offerInstall(
			fmt.Sprintf("%s not found.", name),
			installScript,
			repoDir,
		)
	}
	return nil
}

// checkSysbox checks registration and the services supplied by the Sysbox
// package. Registration alone survives a reboot even when its daemons do not.
// Uses DOCKER_CONTEXT from env (set to colima-membrane on macOS).
func checkSysbox() error {
	out, err := exec.Command("docker", "info", "--format",
		"{{range $k, $v := .Runtimes}}{{$k}}\n{{end}}").Output()
	if err != nil {
		return fmt.Errorf("docker info failed: %w", err)
	}
	if !strings.Contains("\n"+string(out), "\nsysbox-runc\n") {
		return fmt.Errorf("sysbox-runc not registered with Docker")
	}
	args := []string{"systemctl", "is-active", "sysbox.service", "sysbox-mgr.service", "sysbox-fs.service"}
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("colima", append([]string{"ssh", "--profile", "membrane", "--"}, args...)...)
	} else {
		cmd = exec.Command(args[0], args[1:]...)
	}
	// is-active with several units succeeds if *any* is active. Check each line.
	status, err := cmd.CombinedOutput()
	states := strings.Fields(string(status))
	if err != nil || len(states) != 3 || states[0] != "active" || states[1] != "active" || states[2] != "active" {
		detail := strings.TrimSpace(string(status))
		if len(states) == 3 {
			detail = fmt.Sprintf("sysbox.service=%s, sysbox-mgr.service=%s, sysbox-fs.service=%s", states[0], states[1], states[2])
		} else if err != nil {
			detail = fmt.Sprintf("%s (%v)", detail, err)
		}
		return fmt.Errorf("sysbox-runc is registered, but its backing Sysbox services are unavailable: %s; rerun the platform installer", detail)
	}
	return nil
}

// offerInstall prints a message and asks the user if they want to run
// the install script. If yes, runs it. If no, returns an error so
// membrane exits cleanly.
func offerInstall(problem, script, repoDir string) error {
	scriptPath := filepath.Join(repoDir, script)
	if _, err := os.Stat(scriptPath); err != nil {
		return fmt.Errorf("%s\nInstall script not found at %s — try: git clone https://github.com/noperator/membrane",
			problem, scriptPath)
	}

	fmt.Fprintf(os.Stderr, "%s\nRun %s to fix this? [y/N] ", problem, script)
	if !confirm() {
		return fmt.Errorf("dependency check failed: %s", problem)
	}

	cmd := exec.Command("bash", scriptPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install script failed: %w", err)
	}

	return nil
}

// offerStart prints a message and asks the user if they want to start
// the dependency. If yes, runs the start function. If no, returns an
// error.
func offerStart(problem string, start func() error) error {
	fmt.Fprintf(os.Stderr, "%s\nStart it now? [y/N] ", problem)
	if !confirm() {
		return fmt.Errorf("dependency check failed: %s", problem)
	}

	if err := start(); err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}

	return nil
}

// confirm reads a y/Y from stdin. Returns false for anything else.
func confirm() bool {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return false
	}
	r := strings.TrimSpace(scanner.Text())
	return r == "y" || r == "Y"
}
