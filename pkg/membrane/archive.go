package membrane

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// archiveAgent stops writers before exporting the private root. Unlike Docker's
// archive/cp API, export does not read configured volumes or the workload's mount
// namespace. Filter the stream before writing: even hidden private contents at
// installed mount destinations must not enter the retained archive.
func archiveAgent(ctx context.Context, s sessionNames, excluded []string) (retErr error) {
	if len(s.archivePaths) == 0 {
		return nil
	}
	started := time.Now()
	var containers []struct {
		ID         string
		State      struct{ Status string }
		Mounts     []struct{ Destination string }
		HostConfig struct{ Tmpfs map[string]string }
	}
	inspect := func() error {
		out, err := exec.CommandContext(ctx, "docker", "inspect", s.agentContainer).Output()
		if err != nil {
			return fmt.Errorf("inspect archive source: %w", err)
		}
		if err := json.Unmarshal(out, &containers); err != nil {
			return err
		}
		if len(containers) != 1 {
			return errors.New("archive source is unavailable")
		}
		return nil
	}
	if err := inspect(); err != nil {
		return err
	}
	if containers[0].State.Status == "created" {
		fmt.Fprintln(os.Stderr, "membrane: archive skipped: workload never started")
		return nil
	}
	s.agentContainer = containers[0].ID
	// Stopping cannot depend on the archive context: a further cancellation may
	// abandon recovery, but must still leave no workload writers behind.
	out, stopErr := exec.Command("docker", "stop", "-t", "2", s.agentContainer).CombinedOutput()
	if err := stopWorkload(s); err != nil {
		return err
	}
	if stopErr != nil {
		return fmt.Errorf("stop archive source: %s: %w", out, stopErr)
	}
	if err := inspect(); err != nil {
		return err
	}
	if containers[0].State.Status != "exited" {
		return fmt.Errorf("archive source must be stopped, got %s", containers[0].State.Status)
	}
	// The preparation exclusions include image-side aliases and nested mount
	// resolution performed before workload code can alter the filesystem.
	excluded = append([]string{"/dev", "/proc", "/sys", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf"}, excluded...)
	for _, mount := range containers[0].Mounts {
		excluded = append(excluded, path.Clean(mount.Destination))
	}
	for mount := range containers[0].HostConfig.Tmpfs {
		excluded = append(excluded, path.Clean(mount))
	}
	within := func(name, root string) bool {
		return name == root || strings.HasPrefix(name, strings.TrimSuffix(root, "/")+"/")
	}
	isExcluded := func(name string) bool {
		for _, root := range excluded {
			if within(name, root) {
				return true
			}
		}
		return false
	}
	reported := make(map[string]bool)
	for _, mount := range excluded {
		for _, selection := range s.archivePaths {
			if (within(mount, selection) || within(selection, mount)) && !reported[mount] {
				fmt.Fprintf(os.Stderr, "membrane: archive skipped mount %q\n", mount)
				reported[mount] = true
			}
		}
	}
	partial := filepath.Join(s.dir, "artifacts.tar.gz.partial")
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	defer func() {
		retErr = errors.Join(retErr, tw.Close(), gz.Close(), f.Close(), ctx.Err())
		if retErr != nil {
			fmt.Fprintf(os.Stderr, "membrane: incomplete archive retained at %s\n", partial)
			return
		}
		complete := filepath.Join(s.dir, "artifacts.tar.gz")
		if retErr = os.Rename(partial, complete); retErr == nil {
			info, err := os.Stat(complete)
			if err != nil {
				retErr = err
				return
			}
			fmt.Fprintf(os.Stderr, "membrane: archive saved to %s (%d bytes, %s)\n", complete, info.Size(), time.Since(started).Round(time.Millisecond))
		} else {
			fmt.Fprintf(os.Stderr, "membrane: incomplete archive retained at %s\n", partial)
		}
	}()

	found := make(map[string]bool)
	symlinkAncestors := make(map[string]string)
	written := make(map[string]bool)
	pending := make(map[string][]tar.Header)
	// A selected hardlink can name an unselected private file. A second streamed
	// export supplies its bytes without docker cp (which could materialize host
	// mounts), buffering file contents, or retaining the unselected source name.
	for pass := 0; pass < 2; pass++ {
		if pass == 1 && len(pending) == 0 {
			break
		}
		exportCtx, cancel := context.WithCancel(ctx)
		cmd := exec.CommandContext(exportCtx, "docker", "export", s.agentContainer)
		var diagnostic bytes.Buffer
		cmd.Stderr = &diagnostic
		stream, err := cmd.StdoutPipe()
		if err != nil {
			cancel()
			return err
		}
		if err := cmd.Start(); err != nil {
			stream.Close()
			cancel()
			return err
		}
		tr := tar.NewReader(stream)
		var streamErr error
		for {
			if streamErr = ctx.Err(); streamErr != nil {
				break
			}
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				streamErr = err
				break
			}
			name := path.Clean(h.Name)
			if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
				streamErr = fmt.Errorf("unsafe export member %q", h.Name)
				break
			}
			if name == "." {
				continue
			}
			h.Name, h.PAXRecords = name, nil
			absolute := "/" + name
			if pass == 1 {
				links := pending[name]
				if len(links) == 0 {
					continue
				}
				if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeSymlink {
					streamErr = fmt.Errorf("unsupported hardlink target %q", name)
					break
				}
				for i, link := range links {
					if i == 0 {
						link.Typeflag, link.Size, link.Linkname = h.Typeflag, h.Size, h.Linkname
					} else {
						link.Linkname = links[0].Name
					}
					if streamErr = tw.WriteHeader(&link); streamErr != nil {
						break
					}
					if i == 0 {
						streamErr = copyTemplateFile(ctx, tw, tr)
						if streamErr != nil {
							break
						}
					}
				}
				if streamErr != nil {
					break
				}
				delete(pending, name)
				continue
			}
			selected := false
			for _, selection := range s.archivePaths {
				if h.Typeflag == tar.TypeSymlink && absolute != selection && within(selection, absolute) {
					symlinkAncestors[selection] = absolute
				}
				if within(absolute, selection) {
					selected, found[selection] = true, true
				}
			}
			if !selected || isExcluded(absolute) {
				continue
			}
			switch h.Typeflag {
			case tar.TypeReg, tar.TypeDir, tar.TypeSymlink:
			case tar.TypeLink:
				target := path.Clean(h.Linkname)
				if path.IsAbs(target) || target == ".." || strings.HasPrefix(target, "../") {
					streamErr = fmt.Errorf("unsafe hardlink target %q", h.Linkname)
					break
				}
				if isExcluded("/" + target) {
					fmt.Fprintf(os.Stderr, "membrane: archive skipped %q (hardlink target is excluded)\n", absolute)
					continue
				}
				h.Linkname = target
				if !written[target] {
					pending[target] = append(pending[target], *h)
					continue
				}
			default:
				fmt.Fprintf(os.Stderr, "membrane: archive skipped special file %q\n", absolute)
				continue
			}
			if streamErr != nil {
				break
			}
			if streamErr = tw.WriteHeader(h); streamErr != nil {
				break
			}
			if streamErr = copyTemplateFile(ctx, tw, tr); streamErr != nil {
				break
			}
			written[name] = true
		}
		if streamErr == nil {
			// Consume tar padding and check the producer, not just tar's EOF.
			_, streamErr = io.Copy(io.Discard, stream)
		}
		if streamErr != nil {
			cancel()
		}
		stream.Close()
		waitErr := cmd.Wait()
		cancel()
		if err := errors.Join(streamErr, waitErr, ctx.Err()); err != nil {
			return fmt.Errorf("Docker export: %s: %w", strings.TrimSpace(diagnostic.String()), err)
		}
	}
	if len(pending) != 0 {
		return errors.New("Docker export omitted selected hardlink contents")
	}
	for _, selection := range s.archivePaths {
		if isExcluded(selection) {
			continue
		}
		if ancestor := symlinkAncestors[selection]; ancestor != "" {
			fmt.Fprintf(os.Stderr, "membrane: archive skipped %q (symlink ancestor %q)\n", selection, ancestor)
		} else if !found[selection] {
			fmt.Fprintf(os.Stderr, "membrane: archive missing %q (absent or omitted by Docker, such as a socket)\n", selection)
		}
	}
	return nil
}
