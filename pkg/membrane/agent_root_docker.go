package membrane

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// copyAgentRoot overlays a prepared tree onto a never-started container. Docker
// archive operations mount configured volumes even in this state, so exclusions
// are resolved in Docker's own filesystem view before constructing the upload.
// This is exercised on disposable containers; workload activation is separate.
func copyAgentRoot(ctx context.Context, staged, container string, uid, gid int) (retErr error) {
	out, err := exec.CommandContext(ctx, "docker", "inspect", container).Output()
	if err != nil {
		return fmt.Errorf("inspect template destination: %w", err)
	}
	var containers []struct {
		ID         string
		State      struct{ Status string }
		Mounts     []struct{ Destination string }
		HostConfig struct{ Tmpfs map[string]string }
	}
	if err := json.Unmarshal(out, &containers); err != nil {
		return fmt.Errorf("decode template destination: %w", err)
	}
	if len(containers) != 1 || containers[0].State.Status != "created" {
		return errors.New("template destination must be a never-started container")
	}
	container = containers[0].ID
	// The CLI transports the small Engine stat requests using the selected
	// Docker context, including Colima/SSH/TLS, without another client library.
	proxy := exec.CommandContext(ctx, "docker", "system", "dial-stdio")
	var diagnostic bytes.Buffer
	proxy.Stderr = &diagnostic
	in, err := proxy.StdinPipe()
	if err != nil {
		return err
	}
	outPipe, err := proxy.StdoutPipe()
	if err != nil {
		in.Close()
		return err
	}
	if err := proxy.Start(); err != nil {
		in.Close()
		outPipe.Close()
		return err
	}
	defer func() {
		in.Close()
		outPipe.Close()
		if err := proxy.Wait(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("Docker template inspection: %s: %w", strings.TrimSpace(diagnostic.String()), err))
		}
	}()
	reader := bufio.NewReader(outPipe)
	type pathStat struct {
		Mode       os.FileMode
		LinkTarget string
	}
	cache := make(map[string]*pathStat)
	stat := func(name string) (*pathStat, error) {
		if info, ok := cache[name]; ok {
			return info, nil
		}
		req, err := http.NewRequest("HEAD", "http://docker/containers/"+container+"/archive?path="+url.QueryEscape(name), nil)
		if err != nil {
			return nil, err
		}
		if err := req.Write(in); err != nil {
			return nil, err
		}
		response, err := http.ReadResponse(reader, req)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusNotFound {
			cache[name] = nil
			return nil, nil
		}
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("inspect container path %s: %s", name, response.Status)
		}
		data, err := base64.StdEncoding.DecodeString(response.Header.Get("X-Docker-Container-Path-Stat"))
		if err != nil {
			return nil, err
		}
		var info pathStat
		if err := json.Unmarshal(data, &info); err != nil {
			return nil, err
		}
		cache[name] = &info
		return &info, nil
	}

	// Runtime filesystems and Docker-generated host files are never template
	// targets. Include all configured mount kinds, not just Membrane's binds.
	mounts := []string{"/dev", "/proc", "/sys", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf"}
	for _, mount := range containers[0].Mounts {
		mounts = append(mounts, mount.Destination)
	}
	for name := range containers[0].HostConfig.Tmpfs {
		mounts = append(mounts, name)
	}
	sort.Slice(mounts, func(i, j int) bool { return len(mounts[i]) < len(mounts[j]) })
	var excluded []string
	isExcluded := func(name string) bool {
		for _, mount := range excluded {
			if name == mount || strings.HasPrefix(name, strings.TrimSuffix(mount, "/")+"/") {
				return true
			}
		}
		return false
	}
	for _, mount := range mounts {
		// /var/run, for example, can redirect a bind into /run. Exclude both
		// spellings so copying a canonical path cannot reach that host mount.
		resolved := "/"
		for _, component := range strings.Split(strings.TrimPrefix(path.Clean(mount), "/"), "/") {
			resolved = path.Join(resolved, component)
			// Resolve nested mounts too: a link in an earlier mount can send
			// a later mount to an otherwise unrelated private destination.
			info, err := stat(resolved)
			if err != nil {
				return fmt.Errorf("resolve mounted destination %s: %w", mount, err)
			}
			if info != nil && info.Mode&os.ModeSymlink != 0 {
				if !path.IsAbs(info.LinkTarget) {
					return fmt.Errorf("unresolved mounted destination %s: %q", mount, info.LinkTarget)
				}
				resolved = path.Clean(info.LinkTarget)
			}
		}
		excluded = append(excluded, path.Clean(mount), resolved)
	}

	type entry struct {
		name string
		info fs.FileInfo
	}
	var entries []entry
	err = filepath.Walk(staged, func(source string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(staged, source)
		if err != nil {
			return err
		}
		if relative == "." {
			if !info.IsDir() {
				return fmt.Errorf("staged template %s must be a directory", staged)
			}
			return nil
		}
		name := "/" + filepath.ToSlash(relative)
		if isExcluded(name) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported staged template path %s", source)
		}
		if name == "/usr/local/bin/entrypoint.sh" {
			return fmt.Errorf("template path %s is reserved for Membrane startup", name)
		}
		// Walk visits every ancestor first. Reject links even when their target
		// is private, and reject type collisions before sending any file bytes.
		dest, err := stat(name)
		if err != nil {
			return fmt.Errorf("inspect template destination %s: %w", name, err)
		}
		if dest != nil && dest.Mode.Type() != info.Mode().Type() {
			return fmt.Errorf("template destination %s has incompatible type %s (template %s); symlinks and file/directory replacement are not allowed", name, dest.Mode.Type(), info.Mode().Type())
		}
		entries = append(entries, entry{relative, info})
		return nil
	})
	if err != nil || len(entries) == 0 {
		return err
	}

	// Build a private transfer file only after the full plan passes. No template
	// source or parent becomes an agent mount. The tar contains no links/devices.
	f, err := os.CreateTemp(filepath.Dir(staged), "agent-root-*.tar")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	tw := tar.NewWriter(f)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(entry.info, "")
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(entry.name)
		h.Uid, h.Gid, h.Uname, h.Gname = 0, 0, "", ""
		if h.Name == "home/agent" || strings.HasPrefix(h.Name, "home/agent/") {
			h.Uid, h.Gid = uid, gid
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if entry.info.Mode().IsRegular() {
			in, err := os.Open(filepath.Join(staged, entry.name))
			if err != nil {
				return err
			}
			copyErr := copyTemplateFile(ctx, tw, in)
			if err := errors.Join(copyErr, in.Close()); err != nil {
				return err
			}
		}
	}
	if err := errors.Join(tw.Close(), f.Close()); err != nil {
		return err
	}
	f, err = os.Open(f.Name())
	if err != nil {
		return err
	}
	defer f.Close()
	copy := exec.CommandContext(ctx, "docker", "cp", "-", container+":/")
	copy.Stdin = f
	if out, err := copy.CombinedOutput(); err != nil {
		return fmt.Errorf("copy template into container: %s: %w", out, err)
	}
	return nil
}
