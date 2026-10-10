package membrane

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

type workspaceTrustEntry struct {
	Path      string `yaml:"path"`
	Hash      string `yaml:"hash,omitempty"`
	Permanent bool   `yaml:"permanent,omitempty"`
}

type workspaceTrustStore struct {
	Trusted []workspaceTrustEntry `yaml:"trusted"`
}

func workspaceConfigHash(path string, data []byte) string {
	h := sha256.New()
	h.Write([]byte(path))
	h.Write([]byte{0}) // Paths cannot contain NUL; separate the path from the contents.
	h.Write(data)
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

// trustWorkspaceConfig must succeed before any workspace values are merged or expanded.
func trustWorkspaceConfig(home, path string, data []byte) (bool, error) {
	storePath := filepath.Join(home, ".membrane", "trusted-workspaces.yaml")
	store, err := readWorkspaceTrust(storePath)
	if err != nil {
		return false, fmt.Errorf("read workspace trust file %s (repair the file or remove the invalid entry): %w", storePath, err)
	}
	hash := workspaceConfigHash(path, data)
	for _, entry := range store.Trusted {
		if entry.Path == path && (entry.Permanent || entry.Hash == hash) {
			return true, nil
		}
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "membrane: stdin is not a TTY; ignoring untrusted workspace config %s, including its restrictions and permissions; run with TTY stdin to review and trust it\n", path)
		return false, nil
	}
	fmt.Fprintf(os.Stderr, "Workspace config: %s\nTrusting it permits host-side arguments, environment expansion, and additional mounts.\ny = trust this version\nn = ignore the workspace config for this run\np = permanently trust this path, including future changes\nTrust this workspace config? [y/n/p] ", path)
	response, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, nil
	}
	entry := workspaceTrustEntry{Path: path}
	switch strings.TrimSpace(response) {
	case "y":
		entry.Hash = hash
	case "p":
		entry.Permanent = true
	default:
		return false, nil
	}

	entries := store.Trusted[:0]
	for _, old := range store.Trusted {
		if old.Path != path {
			entries = append(entries, old)
		}
	}
	store.Trusted = append(entries, entry)
	if err := writeWorkspaceTrust(storePath, store); err != nil {
		return false, fmt.Errorf("write workspace trust file %s: %w", storePath, err)
	}
	return true, nil
}

func readWorkspaceTrust(path string) (workspaceTrustStore, error) {
	var store workspaceTrustStore
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		return store, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&store); err != nil {
		return store, fmt.Errorf("invalid YAML: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return store, fmt.Errorf("expected a single YAML document")
	}
	seen := make(map[string]bool)
	for _, entry := range store.Trusted {
		if seen[entry.Path] {
			return store, fmt.Errorf("duplicate workspace config path: %q", entry.Path)
		}
		seen[entry.Path] = true
		if !filepath.IsAbs(entry.Path) || filepath.Clean(entry.Path) != entry.Path ||
			strings.ContainsRune(entry.Path, '\x00') || filepath.Base(entry.Path) != ".membrane.yaml" {
			return store, fmt.Errorf("entry path must be an absolute, clean .membrane.yaml path: %q", entry.Path)
		}
		if !entry.Permanent || entry.Hash != "" {
			digest, err := hex.DecodeString(strings.TrimPrefix(entry.Hash, "sha256:"))
			if !strings.HasPrefix(entry.Hash, "sha256:") || err != nil || len(digest) != sha256.Size {
				return store, fmt.Errorf("invalid SHA-256 hash for %s", entry.Path)
			}
		}
	}
	return store, nil
}

func writeWorkspaceTrust(path string, store workspaceTrustStore) error {
	data, err := yaml.Marshal(store)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// CreateTemp uses 0600; rename also replaces any old, broader permissions.
	f, err := os.CreateTemp(filepath.Dir(path), ".trusted-workspaces-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
