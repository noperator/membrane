package membrane

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type config struct {
	DNSResolver string      `yaml:"dns_resolver"`
	SSLInsecure bool        `yaml:"ssl_insecure"`
	Ignore      []string    `yaml:"ignore"`
	Readonly    []string    `yaml:"readonly"`
	Args        []string    `yaml:"args"`
	Allow       []AllowRule `yaml:"allow"`
}

func (c *config) dnsResolver() string {
	if c.DNSResolver != "" {
		return c.DNSResolver
	}
	return "1.1.1.1"
}

// portRule is a port with an explicit transport protocol.
// Proto is "tcp" or "udp"; Port is the port number.
type portRule struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"` // "tcp" or "udp"
}

// AllowRule represents a single entry in the allow list.
// Type is one of "cidr", "host", or "url".
type AllowRule struct {
	Type   string     `json:"type"`
	CIDR   string     `json:"cidr,omitempty"`
	Host   string     `json:"host,omitempty"`
	Ports  []portRule `json:"ports,omitempty"` // nil = any port
	Scheme string     `json:"scheme,omitempty"`
	Path   string     `json:"path,omitempty"`
	HTTP   []HTTPRule `json:"http,omitempty"`
}

type HTTPRule struct {
	Methods []string   `json:"methods,omitempty"`
	Paths   []PathRule `json:"paths,omitempty"`
}

type PathRule struct {
	Path string `json:"path"`
}

func (r *AllowRule) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		return r.parseAuto(value.Value)
	case yaml.MappingNode:
		return r.parseMappingNode(value)
	default:
		return fmt.Errorf("allow entry must be a string or mapping")
	}
}

func (r *AllowRule) parseAuto(s string) error {
	// 1. IP address → CIDR /32
	if net.ParseIP(s) != nil {
		r.Type = "cidr"
		r.CIDR = s + "/32"
		return nil
	}
	// 2. CIDR
	if _, _, err := net.ParseCIDR(s); err == nil {
		r.Type = "cidr"
		r.CIDR = s
		return nil
	}
	// 3. URL
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return fmt.Errorf("invalid URL %q: %w", s, err)
		}
		r.Type = "url"
		r.Scheme = u.Scheme
		r.Host = u.Hostname()
		r.Path = u.Path
		if portStr := u.Port(); portStr != "" {
			p, err := strconv.Atoi(portStr)
			if err != nil {
				return fmt.Errorf("invalid port in URL %q: %w", s, err)
			}
			r.Ports = []portRule{{Port: p, Proto: "tcp"}}
		} else if u.Scheme == "https" {
			r.Ports = []portRule{{Port: 443, Proto: "tcp"}}
		} else if u.Scheme == "http" {
			r.Ports = []portRule{{Port: 80, Proto: "tcp"}}
		}
		if r.Path != "" && r.Path != "/" {
			r.HTTP = []HTTPRule{
				{Paths: []PathRule{{Path: r.Path}}},
			}
		}
		return nil
	}
	// 4. Hostname (possibly with inline port)
	r.Type = "host"
	if host, portStr, err := net.SplitHostPort(s); err == nil {
		r.Host = host
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid port in %q: %w", s, err)
		}
		r.Ports = []portRule{{Port: p, Proto: "tcp"}}
	} else {
		r.Host = s
	}
	return nil
}

func (r *AllowRule) parseMappingNode(value *yaml.Node) error {
	var destStr string
	var portsNode *yaml.Node
	var httpNode *yaml.Node

	for i := 0; i+1 < len(value.Content); i += 2 {
		key := value.Content[i].Value
		val := value.Content[i+1]
		switch key {
		case "dest":
			destStr = val.Value
		case "ports":
			portsNode = val
		case "http":
			httpNode = val
		}
	}

	if destStr == "" {
		return fmt.Errorf("allow mapping entry missing 'dest' key")
	}
	if err := r.parseAuto(destStr); err != nil {
		return err
	}

	if portsNode != nil {
		for _, n := range portsNode.Content {
			pr, err := parsePort(n.Value)
			if err != nil {
				return fmt.Errorf("invalid port %q: %w", n.Value, err)
			}
			r.Ports = appendUniquePort(r.Ports, pr)
		}
	}

	if httpNode != nil {
		r.HTTP = nil
		for _, ruleNode := range httpNode.Content {
			var hr HTTPRule
			for i := 0; i+1 < len(ruleNode.Content); i += 2 {
				key := ruleNode.Content[i].Value
				val := ruleNode.Content[i+1]
				switch key {
				case "methods":
					for _, n := range val.Content {
						hr.Methods = append(hr.Methods, n.Value)
					}
				case "paths":
					for _, n := range val.Content {
						hr.Paths = append(hr.Paths, PathRule{Path: n.Value})
					}
				}
			}
			r.HTTP = append(r.HTTP, hr)
		}
	}

	return nil
}

// parsePort parses a port specifier of the form "443", "443/tcp", or "443/udp".
// A bare integer defaults to TCP. Proto must be "tcp" or "udp".
func parsePort(s string) (portRule, error) {
	proto := "tcp"
	portStr := s
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		portStr = s[:idx]
		proto = s[idx+1:]
		if proto != "tcp" && proto != "udp" {
			return portRule{}, fmt.Errorf("invalid protocol %q: must be tcp or udp", proto)
		}
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return portRule{}, fmt.Errorf("invalid port number %q: %w", portStr, err)
	}
	return portRule{Port: p, Proto: proto}, nil
}

func appendUniquePort(s []portRule, pr portRule) []portRule {
	for _, x := range s {
		if x == pr {
			return s
		}
	}
	return append(s, pr)
}

// ParseAllowEntry parses a raw CLI --allow string into an AllowRule.
func ParseAllowEntry(raw string) (AllowRule, error) {
	var r AllowRule
	return r, r.parseAuto(raw)
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

	if localErr != nil && !localMissing {
		return nil, fmt.Errorf("load local config: %w", localErr)
	}
	if workspaceErr != nil && !workspaceMissing {
		return nil, fmt.Errorf("load workspace config: %w", workspaceErr)
	}

	base := config{}
	if !localMissing {
		base = *localCfg
	}
	if !workspaceMissing {
		base.Ignore = append(base.Ignore, workspace.Ignore...)
		base.Readonly = append(base.Readonly, workspace.Readonly...)
		base.Args = append(base.Args, workspace.Args...)
		base.Allow = append(base.Allow, workspace.Allow...)
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
	for i, arg := range args {
		args[i] = os.ExpandEnv(arg)
	}
}
