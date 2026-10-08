package membrane

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
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
	_, _ = fmt.Fscan(os.Stdin, &response)
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
		_ = exec.Command("docker", "rmi", agentImageName).Run()   // ignore error — may not exist
		_ = exec.Command("docker", "rmi", handlerImageName).Run() // ignore error — may not exist
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
	candidates := []struct{ name, context string }{
		{agentImageName, "docker/agent"},
		{handlerImageName, "docker/handler"},
	}
	var missing []struct{ name, context string }
	for _, img := range candidates {
		out, err := exec.Command("docker", "images", "-q", img.name).Output()
		if err != nil {
			return fmt.Errorf("check docker image %s: %w", img.name, err)
		}
		if strings.TrimSpace(string(out)) == "" {
			missing = append(missing, struct{ name, context string }{img.name, filepath.Join(repoDir, img.context)})
		}
	}
	return buildImagesParallel(missing)
}

// buildImages builds both membrane Docker images from repoDir.
func buildImages(repoDir string) error {
	return buildImagesParallel([]struct{ name, context string }{
		{agentImageName, filepath.Join(repoDir, "docker/agent")},
		{handlerImageName, filepath.Join(repoDir, "docker/handler")},
	})
}

// buildImagesParallel runs docker build concurrently for each (name, context)
// pair. Output from each build is line-prefixed with [name] so the logs
// from interleaved builds can be distinguished.
func buildImagesParallel(builds []struct{ name, context string }) error {
	if len(builds) == 0 {
		return nil
	}
	errs := make(chan error, len(builds))
	for _, b := range builds {
		b := b
		go func() {
			errs <- buildImageFromDir(b.name, b.context)
		}()
	}
	var firstErr error
	for range builds {
		if err := <-errs; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// buildImageFromDir runs docker build, buffering output. On success it
// prints a short summary; on failure it dumps the captured output.
func buildImageFromDir(name, dir string) error {
	fmt.Fprintf(os.Stderr, "Building %s image...\n", name)

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}
	logDir := filepath.Join(home, ".membrane", "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}
	ts := time.Now().Format("20060102-150405")
	logPath := filepath.Join(logDir, fmt.Sprintf("build-%s-%s.log.gz", name, ts))
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("create build log: %w", err)
	}
	defer logFile.Close()

	gzWriter := gzip.NewWriter(logFile)
	defer gzWriter.Close()

	var buf bytes.Buffer
	cmd := exec.Command("docker", "build", "-t", name, dir)
	// BUILDKIT_PROGRESS=plain produces line-oriented output with explicit
	// durations per step — readable from a file and greppable for later
	// analysis. The ANSI-redraw default would render as garbage in a log.
	cmd.Env = append(os.Environ(), "BUILDKIT_PROGRESS=plain")
	mw := io.MultiWriter(&buf, gzWriter)
	cmd.Stdout = mw
	cmd.Stderr = mw

	start := time.Now()
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "--- %s build output ---\n%s--- end ---\n", name, buf.String())
		return fmt.Errorf("docker build %s: %w", name, err)
	}
	fmt.Fprintf(os.Stderr, "Built %s in %s\n", name, time.Since(start).Round(time.Second))
	return nil
}

// writeDefaultFiles initializes independent user-managed copies, never replacing
// existing files or symlinks, including dangling links.
func writeDefaultFiles(membraneHomeDir string) error {
	for _, name := range []string{"config.yaml", "AGENTS.md"} {
		dest := filepath.Join(membraneHomeDir, name)
		if _, err := os.Lstat(dest); err == nil {
			info, err := os.Stat(dest)
			if err != nil {
				return fmt.Errorf("unusable existing %s (check symlink target): %w", dest, err)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("%s must resolve to a regular file", dest)
			}
			continue
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect %s: %w", dest, err)
		}
		data, err := os.ReadFile(filepath.Join(membraneHomeDir, "src", name))
		if err != nil {
			return fmt.Errorf("read default %s: %w", name, err)
		}
		// Exclusive creation also protects originals during concurrent starts.
		f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("create %s: %w", dest, err)
		}
		_, err = f.Write(data)
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return fmt.Errorf("write %s: %w", dest, err)
		}
	}
	return nil
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
