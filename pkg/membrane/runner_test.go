package membrane

import (
	"strings"
	"testing"
)

func TestAgentCgroupParentDockerArgument(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	workspace := t.TempDir()
	cfg := &config{Args: []string{"--cgroup-parent=/configured-parent"}}
	for _, parent := range []string{"/membrane-test", ""} {
		args, err := buildAgentArgs(workspace, &mounts{}, cfg, nil,
			sessionNames{cgroupParent: parent}, "172.20.0.2", false)
		if err != nil {
			t.Fatal(err)
		}
		if parent == "" {
			if args[0] != "run" {
				t.Fatalf("untraced command = %q, want run", args[0])
			}
			continue
		}
		joined := strings.Join(args, " ")
		if args[0] != "create" || !strings.Contains(joined, "--cgroup-parent="+parent) {
			t.Fatalf("missing traced create/parent: %v", args)
		}
		if strings.LastIndex(joined, "--cgroup-parent=") != strings.Index(joined, "--cgroup-parent="+parent) {
			t.Fatalf("configuration overrode session parent: %v", args)
		}
	}
}
