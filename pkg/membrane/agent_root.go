package membrane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// prepareAgentRoot copies host references into private session storage. Only
// ancestor directories participate in cycle detection: repeated references are
// legitimate independent imports, not cycles or hard links.
func prepareAgentRoot(ctx context.Context, source, destination string) (retErr error) {
	source, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil {
		return fmt.Errorf("resolve staging parent: %w", err)
	}
	destination = filepath.Join(parent, filepath.Base(destination))
	// Refuse an existing destination, including links, before taking ownership
	// of cleanup. A failed import must not leave a partial usable template.
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("staging destination %s already exists", destination)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect staging destination %s: %w", destination, err)
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, removePreparedAgentRoot(destination))
		}
	}()
	var copyPath func(string, string, []os.FileInfo) error
	copyPath = func(src, dst string, ancestors []os.FileInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		resolved, err := filepath.EvalSymlinks(src)
		if err != nil {
			return fmt.Errorf("resolve template path %s: %w", src, err)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return fmt.Errorf("inspect template path %s: %w", src, err)
		}
		switch {
		case info.IsDir():
			if relative, err := filepath.Rel(resolved, dst); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return fmt.Errorf("template directory %s contains its staging destination", src)
			}
			for _, ancestor := range ancestors {
				if os.SameFile(info, ancestor) {
					return fmt.Errorf("template directory cycle at %s", src)
				}
			}
			entries, err := os.ReadDir(resolved)
			if err != nil {
				return fmt.Errorf("read template directory %s: %w", src, err)
			}
			// Apply possibly readonly permissions only after copying children.
			if err := os.Mkdir(dst, 0700); err != nil {
				return fmt.Errorf("create staged directory %s: %w", dst, err)
			}
			for _, entry := range entries {
				if err := copyPath(filepath.Join(resolved, entry.Name()), filepath.Join(dst, entry.Name()), append(ancestors, info)); err != nil {
					return err
				}
			}
			return os.Chmod(dst, info.Mode().Perm())
		case info.Mode().IsRegular():
			// A concurrent replacement with a FIFO must not hang preparation.
			in, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NONBLOCK, 0)
			if err != nil {
				return fmt.Errorf("open template file %s: %w", src, err)
			}
			defer in.Close()
			info, err = in.Stat()
			if err != nil {
				return fmt.Errorf("inspect open template file %s: %w", src, err)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("template file %s is no longer a regular file", src)
			}
			out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return fmt.Errorf("create staged file %s: %w", dst, err)
			}
			copyErr := copyTemplateFile(ctx, out, in)
			if err := errors.Join(copyErr, out.Chmod(info.Mode().Perm()), out.Close()); err != nil {
				return fmt.Errorf("copy template file %s: %w", src, err)
			}
			return nil
		default:
			return fmt.Errorf("unsupported template file %s (%s): only regular files and directories are supported", src, info.Mode().Type())
		}
	}
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("inspect agent-root %s: %w", source, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("agent-root %s must be a directory", source)
	}
	return copyPath(source, destination, nil)
}

// Both staging and upload preparation remain cancellable within large files.
// The bound is a transfer chunk size, not a template size limit.
func copyTemplateFile(ctx context.Context, out io.Writer, in io.Reader) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := io.CopyN(out, in, 1024*1024)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Imported directory modes can be readonly. Restore owner access only on the
// independent staged directories so failed preparation and normal teardown can
// remove them. WalkDir does not follow links into any external tree.
func removePreparedAgentRoot(root string) error {
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			return os.Chmod(name, info.Mode().Perm()|0700)
		}
		return nil
	})
	return errors.Join(err, os.RemoveAll(root))
}
