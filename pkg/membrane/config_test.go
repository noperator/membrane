package membrane

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

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
