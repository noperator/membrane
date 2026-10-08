package membrane

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
		filepath.Join(home, ".membrane/config.yaml"): "sealed: [.env]\nreadonly: [config/]\n",
		filepath.Join(workspace, ".membrane.yaml"):   "sealed: [secrets/, '*.pem']\n",
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, skipGlobal := range []bool{false, true} {
		cfg, err := loadConfig(workspace, skipGlobal)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"secrets/", "*.pem"}
		if !skipGlobal {
			want = append([]string{".env"}, want...)
			if !reflect.DeepEqual(cfg.Readonly, []string{"config/"}) {
				t.Fatalf("Readonly = %v", cfg.Readonly)
			}
		}
		if !reflect.DeepEqual(cfg.Sealed, want) {
			t.Fatalf("skipGlobal=%v: Sealed = %v, want %v", skipGlobal, cfg.Sealed, want)
		}
		if got := effectiveFilesystemPolicy(cfg, "secrets", "secrets", policyReadonly); got != policySealed {
			t.Fatalf("loaded sealed selector = %d, want SEALED over READONLY", got)
		}
	}
}

func TestLoadConfigRejectsLegacyPolicy(t *testing.T) {
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
