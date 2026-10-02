package membrane

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFilesystemPolicySelectorsAndPrecedence(t *testing.T) {
	cfg := &config{
		Readonly: []string{"config/", "*.txt", "tree/*/rules.[ch]"},
		Ignore:   []string{"config/secrets.*", ".env", "sealed/"},
	}
	for _, test := range []struct {
		path      string
		inherited uint32
		want      uint32
	}{
		{"config", policyNormal, policyReadonly},
		{"config/settings.yaml", policyReadonly, policyReadonly},
		{"config/secrets.txt", policyReadonly, policySealed},
		{"nested/.env", policyNormal, policySealed},
		{"normal.txt", policyNormal, policyReadonly},
		{"nested/normal.txt", policyNormal, policyReadonly},
		{"tree/x/rules.c", policyNormal, policyReadonly},
		{"tree/x/y/rules.c", policyNormal, policyNormal},
		{"tree/x/rules.go", policyNormal, policyNormal},
		{"nested/config/secrets.bin", policyNormal, policyNormal},
		{"readonly.txt", policySealed, policySealed},
		{"unmatched", policyNormal, policyNormal},
	} {
		t.Run(test.path, func(t *testing.T) {
			got := effectiveFilesystemPolicy(cfg, test.path, filepath.Base(test.path), test.inherited)
			if got != test.want {
				t.Fatalf("policy = %d, want %d", got, test.want)
			}
		})
	}
}

func TestFilesystemPolicyInitialManifest(t *testing.T) {
	root := t.TempDir()
	files := []string{"config/settings.yaml", "config/secrets.txt", "sealed/nested/public.txt", "ordinary"}
	for _, path := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0000); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config{Readonly: []string{"config/", "sealed/nested/"}, Ignore: []string{"config/secrets.txt", "sealed/"}}
	got, err := resolveFilesystemPolicy(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []filesystemPolicyEntry{
		{Path: "config", Mode: policyReadonly},
		{Path: "config/secrets.txt", Mode: policySealed},
		{Path: "config/settings.yaml", Mode: policyReadonly},
		{Path: "sealed", Mode: policySealed},
		{Path: "sealed/nested", Mode: policySealed},
		{Path: "sealed/nested/public.txt", Mode: policySealed},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("manifest = %#v, want %#v", got, want)
	}
	if _, err := resolveFilesystemPolicy(filepath.Join(root, "missing"), cfg); err == nil {
		t.Fatal("missing workspace must fail initial enrollment")
	}
}

func TestFilesystemPolicySymlinkTargets(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "tree/sub"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tree/sub/data"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("tree", filepath.Join(root, "sealed-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", filepath.Join(root, "ordinary-dangling")); err != nil {
		t.Fatal(err)
	}
	got, err := resolveFilesystemPolicy(root, &config{Ignore: []string{"sealed-link"}, Readonly: []string{"tree/"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []filesystemPolicyEntry{
		{Path: "sealed-link", Mode: policySealed, NoFollow: true},
		{Path: "tree", Mode: policySealed},
		{Path: "tree/sub", Mode: policySealed},
		{Path: "tree/sub/data", Mode: policySealed},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("manifest = %#v, want %#v", got, want)
	}
	links, err := resolveFilesystemPolicy(root, &config{Ignore: []string{"ordinary-dangling"}})
	if err != nil || !reflect.DeepEqual(links, []filesystemPolicyEntry{{Path: "ordinary-dangling", Mode: policySealed, NoFollow: true}}) {
		t.Fatalf("dangling link snapshot = %#v, %v", links, err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveFilesystemPolicy(root, &config{Ignore: []string{"outside"}}); err == nil {
		t.Fatal("an escaping protected link must not be silently skipped")
	}
}
