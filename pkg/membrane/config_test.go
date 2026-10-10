package membrane

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty/v2"
)

func TestWriteDefaultFiles(t *testing.T) {
	for _, configState := range []string{"missing", "file", "symlink"} {
		for _, agentsState := range []string{"missing", "file", "symlink"} {
			t.Run(configState+"/"+agentsState, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.Mkdir(filepath.Join(dir, "src"), 0755); err != nil {
					t.Fatal(err)
				}
				states := map[string]string{"config.yaml": configState, "AGENTS.md": agentsState}
				for name, state := range states {
					if err := os.WriteFile(filepath.Join(dir, "src", name), []byte("shipped "+name), 0644); err != nil {
						t.Fatal(err)
					}
					dest := filepath.Join(dir, name)
					if state == "symlink" {
						if err := os.Symlink(name+".user", dest); err != nil {
							t.Fatal(err)
						}
						dest += ".user"
					}
					if state != "missing" {
						if err := os.WriteFile(dest, []byte("user "+name), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				for start := 0; start < 2; start++ {
					if err := writeDefaultFiles(dir); err != nil {
						t.Fatal(err)
					}
					for name, state := range states {
						want := "user " + name
						if state == "missing" {
							want = "shipped " + name
						}
						data, err := os.ReadFile(filepath.Join(dir, name))
						if err != nil || string(data) != want {
							t.Fatalf("%s on start %d: %q, %v", name, start, data, err)
						}
						if state == "symlink" {
							target, err := os.Readlink(filepath.Join(dir, name))
							if err != nil || target != name+".user" {
								t.Fatalf("replaced symlink %s: %s, %v", name, target, err)
							}
						}
						// A subsequent repository update must not refresh either copy.
						if err := os.WriteFile(filepath.Join(dir, "src", name), []byte("updated"), 0644); err != nil {
							t.Fatal(err)
						}
					}
				}
			})
		}
	}
}

func TestWriteDefaultFilesRejectsUnusableLinks(t *testing.T) {
	for _, name := range []string{"config.yaml", "AGENTS.md"} {
		for _, target := range []string{"missing", name, "src"} {
			t.Run(name+"/"+target, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.Mkdir(filepath.Join(dir, "src"), 0755); err != nil {
					t.Fatal(err)
				}
				for _, source := range []string{"config.yaml", "AGENTS.md"} {
					if err := os.WriteFile(filepath.Join(dir, "src", source), []byte("shipped"), 0644); err != nil {
						t.Fatal(err)
					}
				}
				link := filepath.Join(dir, name)
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				if err := writeDefaultFiles(dir); err == nil || !strings.Contains(err.Error(), link) {
					t.Fatalf("expected error identifying unusable link %s: %v", link, err)
				}
				if got, err := os.Readlink(link); err != nil || got != target {
					t.Fatalf("modified unusable link: %s, %v", got, err)
				}
				if _, err := os.Lstat(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
					t.Fatalf("created a dangling link's target: %v", err)
				}
			})
		}
	}
}

func TestLoadConfigSealed(t *testing.T) {
	home, workspace := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	if err := os.Mkdir(filepath.Join(home, ".membrane"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{
		filepath.Join(home, ".membrane/config.yaml"): "sealed: [.env]\nreadonly: [config/]\nmounts: [{path: ../global, mode: ro}, {type: git-root, mode: ro}]\n",
		filepath.Join(workspace, ".membrane.yaml"):   "sealed: [secrets/, '*.pem']\nmounts: [{path: ../local}]\n",
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	trustConfigFixture(t, home, workspace)
	for _, skipGlobal := range []bool{false, true} {
		cfg, err := loadConfig(workspace, skipGlobal)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"secrets/", "*.pem"}
		wantMounts := []directoryMount{{Path: "../local", Mode: "rw"}}
		if !skipGlobal {
			wantMounts = append([]directoryMount{{Path: "../global", Mode: "ro"}, {Type: "git-root", Mode: "ro"}}, wantMounts...)
			want = append([]string{".env"}, want...)
			if !reflect.DeepEqual(cfg.Readonly, []string{"config/"}) {
				t.Fatalf("Readonly = %v", cfg.Readonly)
			}
		}
		if !reflect.DeepEqual(cfg.Mounts, wantMounts) {
			t.Fatalf("skipGlobal=%v: Mounts = %v, want %v", skipGlobal, cfg.Mounts, wantMounts)
		}
		if !reflect.DeepEqual(cfg.Sealed, want) {
			t.Fatalf("skipGlobal=%v: Sealed = %v, want %v", skipGlobal, cfg.Sealed, want)
		}
		if got := effectiveFilesystemPolicy(cfg, workspace, filepath.Join(workspace, "secrets"), "secrets", policyReadonly); got != policySealed {
			t.Fatalf("loaded sealed selector = %d, want SEALED over READONLY", got)
		}
	}
}

func TestMountValidation(t *testing.T) {
	for _, test := range []struct {
		mounts string
		want   []directoryMount
	}{
		{"[{path: .}]", []directoryMount{{Path: ".", Mode: "rw"}}},
		{"[{type: git-root}]", []directoryMount{{Type: "git-root", Mode: "rw"}}},
		{"[{type: git-root, mode: ro}]", []directoryMount{{Type: "git-root", Mode: "ro"}}},
		{"[null]", nil}, {"[{}]", nil}, {"[{mode: ro}]", nil},
		{"[{path: '', type: git-root}]", nil}, {"[{path: ., type: ''}]", nil},
		{"[{path: ., type: git-root}]", nil}, {"[{path: null, type: git-root}]", nil},
		{"[{type: unknown}]", nil}, {"[{type: ''}]", nil}, {"[{type: null}]", nil},
		{"[{type: 1}]", nil}, {"[{type: true}]", nil}, {"[{type: []}]", nil},
		{"[{type: git-root, typo: ro}]", nil},
		{"[{type: git-root, mode: ''}]", nil}, {"[{type: git-root, mode: null}]", nil},
		{"[{type: git-root, mode: read}]", nil},
		{"[{path: ''}]", nil}, {"[{path: null}]", nil}, {"[{path: 1}]", nil},
		{"[{path: ., mode: ''}]", nil}, {"[{path: ., mode: null}]", nil}, {"[{path: ., mode: RO}]", nil},
		{"[{path: ., mode: read}]", nil}, {"[{path: ., mode: true}]", nil}, {"[{path: ., typo: ro}]", nil},
		{"[.]", nil}, {"{path: .}", nil}, {"[{path: []}]", nil}, {"[{path: ., mode: []}]", nil},
	} {
		t.Run(test.mounts, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("mounts: "+test.mounts+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadConfigFile(path)
			if test.want != nil {
				if err != nil || !reflect.DeepEqual(cfg.Mounts, test.want) {
					t.Fatalf("mount config: %v, %v; want %v", cfg, err, test.want)
				}
			} else if err == nil || !strings.Contains(err.Error(), path) {
				t.Fatalf("invalid mounts must identify config file: %v", err)
			}
		})
	}
}

func TestLoadConfigRejectsLegacyPolicy(t *testing.T) {
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin = previous; stdin.Close() })
	for _, location := range []string{"global", "workspace"} {
		for _, data := range []string{
			"ignore: [.env]\n",
			"sealed: [secrets/]\nignore: [.env]\n",
			"ignore: []\n",
			"ignore: null\n",
			"<<: {ignore: [.env]}\n",
		} {
			t.Run(location+"/"+strings.TrimSpace(data), func(t *testing.T) {
				home, workspace := t.TempDir(), t.TempDir()
				t.Setenv("HOME", home)
				path := filepath.Join(workspace, ".membrane.yaml")
				if location == "global" {
					if err := os.Mkdir(filepath.Join(home, ".membrane"), 0700); err != nil {
						t.Fatal(err)
					}
					path = filepath.Join(home, ".membrane/config.yaml")
				}
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				if location == "workspace" {
					cfg, err := loadConfig(workspace, false)
					if err != nil || cfg == nil || !reflect.DeepEqual(*cfg, config{}) {
						t.Fatalf("untrusted config must be ignored before parsing: cfg=%+v err=%v", cfg, err)
					}
					trustConfigFixture(t, home, workspace)
				}
				cfg, err := loadConfig(workspace, false)
				if cfg != nil || err == nil || !strings.Contains(err.Error(), path) ||
					!strings.Contains(err.Error(), "field ignore not found") {
					t.Fatalf("legacy config must fail with its path and key: cfg=%+v err=%v", cfg, err)
				}
			})
		}
	}
}

func TestLoadEmptyConfig(t *testing.T) {
	for _, data := range []string{"", "# No workspace overrides.\n", "{}\n"} {
		path := filepath.Join(t.TempDir(), ".membrane.yaml")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := loadConfigFile(path)
		if err != nil || cfg == nil || !reflect.DeepEqual(*cfg, config{}) {
			t.Fatalf("empty config %q: cfg=%+v err=%v", data, cfg, err)
		}
	}
}

func TestDenyConfig(t *testing.T) {
	home, workspace := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	if err := os.Mkdir(filepath.Join(home, ".membrane"), 0700); err != nil {
		t.Fatal(err)
	}
	global := "allow: ['*']\ndeny: [https://api.example.com/v1/]\n"
	local := "allow: [api.example.com]\ndeny: [{dest: '*.example.com', ports: [443], http: [{methods: [GET, POST], paths: [v1, /v2]}]}]\n"
	for path, contents := range map[string]string{
		filepath.Join(home, ".membrane/config.yaml"): global,
		filepath.Join(workspace, ".membrane.yaml"):   local,
	} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	trustConfigFixture(t, home, workspace)
	for _, skip := range []bool{false, true} {
		cfg, err := loadConfig(workspace, skip)
		if err != nil {
			t.Fatal(err)
		}
		want := 2
		if skip {
			want = 1
		}
		if len(cfg.Deny) != want || len(cfg.Allow) != want {
			t.Fatalf("skip=%v: %+v", skip, cfg)
		}
		if !skip && (cfg.Deny[0].Path != "/v1/" || cfg.Deny[0].Ports[0] != (portRule{443, "tcp"})) {
			t.Fatalf("URL deny: %+v", cfg.Deny[0])
		}
		rule := cfg.Deny[want-1]
		if rule.Type != "host-pattern" || rule.Ports[0] != (portRule{443, "tcp"}) || len(rule.HTTP[0].Methods) != 2 || len(rule.HTTP[0].Paths) != 2 {
			t.Fatalf("object deny: %+v", rule)
		}
	}
	for _, rules := range []string{"[example.com, 192.0.2.1, 192.0.2.0/24, '*', https://api.example.com/v1]", "[]", "null"} {
		path := filepath.Join(workspace, "rules.yaml")
		if err := os.WriteFile(path, []byte("allow: "+rules+"\ndeny: "+rules+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := loadConfigFile(path)
		if err != nil || !reflect.DeepEqual(cfg.Allow, cfg.Deny) {
			t.Fatalf("same grammar: cfg=%+v err=%v", cfg, err)
		}
	}
}

// Deny-only validation must not tighten the existing allow grammar.
func TestDenyValidation(t *testing.T) {
	for _, rules := range []string{
		"[null]", "['']", "[{dest: example.com, http: [{methods: [{}]}]}]",
		"[{dest: example.com, ports: [53/udp], http: [{methods: [GET]}]}]",
		"[{dest: https://example.com/v1, ports: [443/udp], http: []}]",
		"[{dest: example.com, ports: [443, 443/udp], http: [{paths: [/v1]}]}]",
	} {
		for _, key := range []string{"allow", "deny"} {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(key+": "+rules+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := loadConfigFile(path)
			if (err != nil) != (key == "deny") {
				t.Fatalf("%s: %s: %v", key, rules, err)
			}
			if key == "deny" && strings.Contains(rules, "/udp") && !strings.Contains(err.Error(), "UDP ports cannot be combined") {
				t.Fatalf("unclear UDP error: %v", err)
			}
		}
	}
}

// These parser/merge fixtures explicitly trust only the bytes under test.
func trustConfigFixture(t *testing.T, home, workspace string) {
	t.Helper()
	path := filepath.Join(workspace, ".membrane.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store := workspaceTrustStore{Trusted: []workspaceTrustEntry{{Path: path, Hash: workspaceConfigHash(path, data)}}}
	if err := writeWorkspaceTrust(filepath.Join(home, ".membrane/trusted-workspaces.yaml"), store); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigUsesApprovedBytes(t *testing.T) {
	home, workspace := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(workspace, ".membrane.yaml")
	data := []byte("args: [-e, APPROVED=original]\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	stdin, stderr := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = slave, writer
	defer func() { os.Stdin, os.Stderr = stdin, stderr }()

	// Wait until the bytes have been read and the trust decision is pending.
	// Closing the PTY and pipe on timeout also unblocks either side on failure.
	timer := time.AfterFunc(5*time.Second, func() { master.Close(); reader.Close() })
	defer timer.Stop()
	done := make(chan error, 1)
	go func() {
		var prompt strings.Builder
		var b [1]byte
		for !strings.HasSuffix(prompt.String(), "Trust this workspace config? [y/n/p] ") {
			if _, err := io.ReadFull(reader, b[:]); err != nil {
				done <- fmt.Errorf("wait for trust prompt: %w", err)
				return
			}
			prompt.WriteByte(b[0])
		}
		if err := os.WriteFile(path, []byte("args: [-e, APPROVED=replaced]\n"), 0600); err != nil {
			done <- err
			master.Close()
			return
		}
		_, err := master.Write([]byte("y\n"))
		done <- err
	}()
	cfg, err := loadConfig(workspace, true)
	if promptErr := <-done; promptErr != nil {
		t.Fatal(promptErr)
	}
	if err != nil || cfg == nil || !reflect.DeepEqual(cfg.Args, []string{"-e", "APPROVED=original"}) {
		t.Fatalf("must parse approved snapshot: cfg=%+v err=%v", cfg, err)
	}
	store, err := readWorkspaceTrust(filepath.Join(home, ".membrane/trusted-workspaces.yaml"))
	if err != nil || len(store.Trusted) != 1 || store.Trusted[0].Hash != workspaceConfigHash(path, data) {
		t.Fatalf("must trust the parsed snapshot: store=%+v err=%v", store, err)
	}
}
