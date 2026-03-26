package membrane

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	repoURL          = "https://github.com/noperator/membrane.git"
	apiURL           = "https://api.github.com/repos/noperator/membrane/commits/main"
	agentImageName   = "membrane-agent"
	handlerImageName = "membrane-handler"
)

// Reset removes selected membrane state. components is a string of
// single-character codes: c=containers, i=image, d=directory.
// Empty string means all components.
func Reset(components string) error {

	if runtime.GOOS == "darwin" {
		os.Setenv("DOCKER_CONTEXT", "colima-membrane")
	}

	for _, r := range components {
		if !strings.ContainsRune("cid", r) {
			return fmt.Errorf("unknown reset component %q (valid: c=containers, i=image, d=directory)", string(r))
		}
	}

	all := components == ""
	doC := all || strings.ContainsRune(components, 'c')
	doI := all || strings.ContainsRune(components, 'i')
	doD := all || strings.ContainsRune(components, 'd')

	fmt.Fprintf(os.Stderr, "This will remove:\n")
	if doC {
		fmt.Fprintf(os.Stderr, "  c - all running membrane containers\n")
	}
	if doI {
		fmt.Fprintf(os.Stderr, "  i - the membrane Docker images\n")
	}
	if doD {
		fmt.Fprintf(os.Stderr, "  d - ~/.membrane\n")
	}
	fmt.Fprintf(os.Stderr, "\nWorkspace .membrane.yaml files are not affected.\n\nContinue? [y/N] ")

	var response string
	fmt.Fscan(os.Stdin, &response)
	if response != "y" && response != "Y" {
		fmt.Fprintf(os.Stderr, "Aborted.\n")
		return nil
	}

	if doC {
		for _, img := range []string{agentImageName, handlerImageName} {
			out, err := exec.Command("docker", "ps", "-q", "--filter", "ancestor="+img).Output()
			if err != nil {
				return fmt.Errorf("list containers: %w", err)
			}
			for _, id := range strings.Fields(string(out)) {
				if err := exec.Command("docker", "rm", "-f", id).Run(); err != nil {
					return fmt.Errorf("remove container %s: %w", id, err)
				}
			}
		}
	}

	if doI {
		exec.Command("docker", "rmi", agentImageName).Run()   // ignore error — may not exist
		exec.Command("docker", "rmi", handlerImageName).Run() // ignore error — may not exist
	}

	if doD {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir: %w", err)
		}
		if err := os.RemoveAll(filepath.Join(home, ".membrane")); err != nil {
			return fmt.Errorf("remove ~/.membrane: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "Reset complete. Run membrane again to start fresh.\n")
	return nil
}

// membraneHome returns the path to ~/.membrane, creating it if necessary.
func membraneHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	dir := filepath.Join(home, ".membrane")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	return dir, nil
}

// ensureRepo clones the repo to ~/.membrane/src if not present.
func ensureRepo() (string, error) {
	home, err := membraneHome()
	if err != nil {
		return "", err
	}

	srcDir := filepath.Join(home, "src")
	gitDir := filepath.Join(srcDir, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		return srcDir, nil // already cloned
	}

	fmt.Fprintf(os.Stderr, "Cloning membrane repo to %s...\n", srcDir)

	cmd := exec.Command("git", "clone", repoURL, srcDir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git clone: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Repo cloned to %s — edit %s to customize.\n",
		srcDir, filepath.Join(home, "config.yaml"))
	return srcDir, nil
}

// remoteCommit fetches the latest commit SHA on main from the GitHub API.
func remoteCommit() (string, error) {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch remote commit: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned %d", resp.StatusCode)
	}

	var result struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	return result.SHA, nil
}

// update does a git pull in repoDir.
func update(repoDir string) error {
	cmd := exec.Command("git", "-C", repoDir, "pull", "--ff-only")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ensureImages checks if both membrane Docker images exist locally.
// Builds any that are missing from repoDir.
func ensureImages(repoDir string) error {
	for _, img := range []struct{ name, context string }{
		{agentImageName, "docker/agent"},
		{handlerImageName, "docker/handler"},
	} {
		out, err := exec.Command("docker", "images", "-q", img.name).Output()
		if err != nil {
			return fmt.Errorf("check docker image %s: %w", img.name, err)
		}
		if strings.TrimSpace(string(out)) != "" {
			continue
		}
		if err := buildImageFromDir(img.name, filepath.Join(repoDir, img.context)); err != nil {
			return err
		}
	}
	return nil
}

// buildImages builds both membrane Docker images from repoDir.
func buildImages(repoDir string) error {
	if err := buildImageFromDir(agentImageName, filepath.Join(repoDir, "docker/agent")); err != nil {
		return err
	}
	return buildImageFromDir(handlerImageName, filepath.Join(repoDir, "docker/handler"))
}

// buildImageFromDir runs docker build -t name dir.
func buildImageFromDir(name, dir string) error {
	fmt.Fprintf(os.Stderr, "Building %s image...\n", name)
	cmd := exec.Command("docker", "build", "-t", name, dir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker build %s: %w", name, err)
	}
	return nil
}

// writeDefaultConfig writes ~/.membrane/config.yaml if it doesn't already exist,
// reading the template from ~/.membrane/src/config-default.yaml.
func writeDefaultConfig(membraneHomeDir string) error {
	dest := filepath.Join(membraneHomeDir, "config.yaml")
	if _, err := os.Stat(dest); err == nil {
		return nil // already exists, never overwrite
	}
	src := filepath.Join(membraneHomeDir, "src", "config-default.yaml")
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read default config: %w", err)
	}
	return os.WriteFile(dest, data, 0644)
}

// isDirty returns true if the git repo at dir has uncommitted changes.
func isDirty(dir string) (bool, error) {
	out, err := exec.Command("git", "-C", dir, "status", "--porcelain").Output()
	if err != nil {
		return false, fmt.Errorf("git status: %w", err)
	}
	return len(strings.TrimSpace(string(out))) > 0, nil
}

// backupSrc copies srcDir to srcDir.<timestamp>.bak.
func backupSrc(srcDir string) error {
	timestamp := time.Now().Format("20060102-150405")
	dest := srcDir + "." + timestamp + ".bak"
	fsys := os.DirFS(srcDir)
	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}
	if err := copyFS(dest, fsys); err != nil {
		return fmt.Errorf("backup src: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Backed up %s to %s\n", srcDir, dest)
	return nil
}

// copyFS copies all files from src into destDir, preserving structure.
func copyFS(destDir string, src fs.FS) error {
	return fs.WalkDir(src, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dest := filepath.Join(destDir, path)
		if d.IsDir() {
			return os.MkdirAll(dest, 0755)
		}
		data, err := fs.ReadFile(src, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return os.WriteFile(dest, data, info.Mode())
	})
}
