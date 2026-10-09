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
		Sealed:   []string{"config/secrets.*", ".env", "sealed/"},
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
		{"nested/config/secrets.bin", policyNormal, policySealed},
		{"readonly.txt", policySealed, policySealed},
		{"unmatched", policyNormal, policyNormal},
	} {
		t.Run(test.path, func(t *testing.T) {
			got := effectiveFilesystemPolicy(cfg, "/workspace", filepath.Join("/workspace", test.path), test.path, test.inherited)
			if got != test.want {
				t.Fatalf("policy = %d, want %d", got, test.want)
			}
		})
	}
}

func TestFilesystemSelectorAnchors(t *testing.T) {
	workspace := "/projects/main [repo]"
	for _, test := range []struct {
		pattern, path, relative string
		want                    bool
	}{
		{".env", "/projects/other/nested/.env", "other/nested/.env", true},
		{".git/", "/projects/other/.git", "other/.git", true},
		{"...env", "/projects/other/...env", "other/...env", true},
		{"secrets/credentials.json", "/projects/other/nested/secrets/credentials.json", "other/nested/secrets/credentials.json", true},
		{"secrets/credentials.json", "/projects/other/mysecrets/credentials.json", "other/mysecrets/credentials.json", false},
		{"secrets/*.json", "/projects/other/secrets/deep/credentials.json", "other/secrets/deep/credentials.json", false},
		{"tree/*/rules.[ch]", "/projects/other/tree/x/rules.c", "other/tree/x/rules.c", true},
		{"./.env", workspace + "/.env", "main [repo]/.env", true},
		{"./.env", workspace + "/nested/.env", "main [repo]/nested/.env", false},
		{"./.env", "/projects/other/.env", "other/.env", false},
		{"./.git/", workspace + "/.git", "main [repo]/.git", true},
		{"./secrets/credentials.json", workspace + "/secrets/credentials.json", "main [repo]/secrets/credentials.json", true},
		{"./secrets/credentials.json", "/projects/other/secrets/credentials.json", "other/secrets/credentials.json", false},
		{"../other/./nested/../*.json", "/projects/other/credentials.json", "other/credentials.json", true},
		{"../../projects/other/.env", "/projects/other/.env", "other/.env", true},
		{"/projects/other/./nested/../.env", "/projects/other/.env", "other/.env", true},
		{"/projects/other/.env", "/projects/other/nested/.env", "other/nested/.env", false},
		{"projects/other/.env", "/projects/other/.env", "other/.env", false},
	} {
		if got := matchesAny(workspace, test.path, test.relative, []string{test.pattern}); got != test.want {
			t.Errorf("%q against %q: got %v, want %v", test.pattern, test.path, got, test.want)
		}
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
	cfg := &config{Readonly: []string{"config/", "sealed/nested/"}, Sealed: []string{"config/secrets.txt", "sealed/"}}
	got, err := resolveFilesystemPolicy(root, cfg, []directoryMount{{Path: root, Mode: "rw"}})
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
	if _, err := resolveFilesystemPolicy(filepath.Join(root, "missing"), cfg, []directoryMount{{Path: filepath.Join(root, "missing"), Mode: "rw"}}); err == nil {
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
	got, err := resolveFilesystemPolicy(root, &config{Sealed: []string{"sealed-link"}, Readonly: []string{"tree/"}}, []directoryMount{{Path: root, Mode: "rw"}})
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
	links, err := resolveFilesystemPolicy(root, &config{Sealed: []string{"ordinary-dangling"}}, []directoryMount{{Path: root, Mode: "rw"}})
	if err != nil || !reflect.DeepEqual(links, []filesystemPolicyEntry{{Path: "ordinary-dangling", Mode: policySealed, NoFollow: true}}) {
		t.Fatalf("dangling link snapshot = %#v, %v", links, err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveFilesystemPolicy(root, &config{Sealed: []string{"outside"}}, []directoryMount{{Path: root, Mode: "rw"}}); err == nil {
		t.Fatal("an escaping protected link must not be silently skipped")
	}
}

// Resolve overlap before inode enrollment, even when an ancestor contains a
// symlink to the writable subtree. Explicit selectors still inherit there.
func TestReadonlyMountSnapshot(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(parent, "worktree")
	for _, dir := range []string{workspace, filepath.Join(workspace, "locked/child"), filepath.Join(parent, "empty")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"sibling", "worktree/ordinary", "worktree/locked/child/secret"} {
		if err := os.WriteFile(filepath.Join(parent, path), []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("worktree", filepath.Join(parent, "alias")); err != nil {
		t.Fatal(err)
	}
	cfg := &config{Readonly: []string{"locked/"}, Sealed: []string{"secret"}}
	for _, reverse := range []bool{false, true} {
		configured := []directoryMount{{Path: parent, Mode: "ro"}, {Path: "locked/child", Mode: "rw"}, {Path: "../empty", Mode: "ro"}}
		if reverse {
			configured[0], configured[2] = configured[2], configured[0]
		}
		mounts, err := resolveMounts(workspace, configured)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := resolveFilesystemPolicy(workspace, cfg, mounts)
		if err != nil {
			t.Fatal(err)
		}
		got := make(map[string]uint32)
		for _, entry := range entries {
			path := filepath.Join(mounts[entry.Root].Path, entry.Path)
			if entry.Mode > got[path] {
				got[path] = entry.Mode
			}
		}
		want := map[string]uint32{
			parent: policyReadonly, filepath.Join(parent, "sibling"): policyReadonly,
			filepath.Join(parent, "alias"): policyReadonly, filepath.Join(parent, "empty"): policyReadonly,
			filepath.Join(workspace, "locked"):              policyReadonly,
			filepath.Join(workspace, "locked/child"):        policyReadonly,
			filepath.Join(workspace, "locked/child/secret"): policySealed,
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("reverse=%v: snapshot = %v, want %v", reverse, got, want)
		}
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(parent, "outside")); err != nil {
		t.Fatal(err)
	}
	mounts, err := resolveMounts(workspace, []directoryMount{{Path: parent, Mode: "ro"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolveFilesystemPolicy(workspace, cfg, mounts); err == nil {
		t.Fatal("readonly mount must reject an escaping protected symlink")
	}
}
