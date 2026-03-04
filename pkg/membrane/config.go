package membrane

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type config struct {
	Ignore    []string `yaml:"ignore"`
	Readonly  []string `yaml:"readonly"`
	Args      []string `yaml:"args"`
	Hostnames []string `yaml:"hostnames"`
}

// loadConfig loads and merges local (~/.membrane/config.yaml) and workspace
// (.membrane.yaml) configs. Workspace config lists are appended to local lists.
func loadConfig(workspaceDir string) (*config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}

	localPath := filepath.Join(home, ".membrane", "config.yaml")
	workspacePath := filepath.Join(workspaceDir, ".membrane.yaml")

	localCfg, localErr := loadConfigFile(localPath)
	workspace, workspaceErr := loadConfigFile(workspacePath)

	localMissing := os.IsNotExist(localErr)
	workspaceMissing := os.IsNotExist(workspaceErr)

	// Return actual errors (not "file not found").
	if localErr != nil && !localMissing {
		return nil, fmt.Errorf("load local config: %w", localErr)
	}
	if workspaceErr != nil && !workspaceMissing {
		return nil, fmt.Errorf("load workspace config: %w", workspaceErr)
	}

	// Start from local (or empty if missing), append workspace.
	base := config{}
	if !localMissing {
		base = *localCfg
	}
	if !workspaceMissing {
		base.Ignore = append(base.Ignore, workspace.Ignore...)
		base.Readonly = append(base.Readonly, workspace.Readonly...)
		base.Args = append(base.Args, workspace.Args...)
		base.Hostnames = append(base.Hostnames, workspace.Hostnames...)
	}

	expandArgs(base.Args)
	return &base, nil
}

func loadConfigFile(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

func expandArgs(args []string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	for i, arg := range args {
		if strings.HasPrefix(arg, "~/") {
			args[i] = filepath.Join(home, arg[2:])
		} else if strings.HasPrefix(arg, "$HOME/") {
			args[i] = filepath.Join(home, arg[6:])
		} else if arg == "~" {
			args[i] = home
		} else if arg == "$HOME" {
			args[i] = home
		}
	}
}
