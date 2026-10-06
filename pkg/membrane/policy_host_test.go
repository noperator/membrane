package membrane

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func hostFixtureCommand(t *testing.T, dir, name, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
}

func TestBPFLSMPreflight(t *testing.T) {
	for _, test := range []struct {
		name, lsms, procConfig, bootConfig, want string
	}{
		{"active without config", "capability,bpf", "", "", ""},
		{"active with config", "bpf,yama", "CONFIG_BPF_LSM=y", "", ""},
		{"inactive proc config", "yama", "CONFIG_BPF_LSM=y", "", "supported but not active"},
		{"inactive boot config", "yama", "", "CONFIG_BPF_LSM=y", "supported but not active"},
		{"unsupported", "yama", "# CONFIG_BPF_LSM is not set", "", "does not support BPF LSM"},
		{"proc config takes precedence", "yama", "CONFIG_BPF_LSM=y", "# CONFIG_BPF_LSM is not set", "supported but not active"},
		{"unknown", "yama", "", "", "cannot determine kernel BPF LSM support"},
		{"unreadable lsm list", "", "", "", "cannot determine kernel BPF LSM support"},
		{"unreadable lsm list with support", "", "CONFIG_BPF_LSM=y", "", "check the Docker host's securityfs mount"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			hostFixtureCommand(t, dir, "cat", `case "$1" in
/sys/kernel/security/lsm) [ -n "$TEST_LSMS" ] && printf '%s\n' "$TEST_LSMS" ;;
/boot/config-*) [ -n "$TEST_BOOT_CONFIG" ] && printf '%s\n' "$TEST_BOOT_CONFIG" ;;
*) exit 1 ;;
esac
`)
			hostFixtureCommand(t, dir, "gzip", `[ -n "$TEST_PROC_CONFIG" ] && printf '%s\n' "$TEST_PROC_CONFIG"`)
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("TEST_LSMS", test.lsms)
			t.Setenv("TEST_PROC_CONFIG", test.procConfig)
			t.Setenv("TEST_BOOT_CONFIG", test.bootConfig)
			cmd := exec.Command("sh", "-seu")
			cmd.Stdin = strings.NewReader(bpfLSMPreflight)
			out, err := cmd.CombinedOutput()
			if test.want == "" {
				if err != nil {
					t.Fatalf("preflight failed: %s: %v", out, err)
				}
			} else if err == nil || !strings.Contains(string(out), test.want) {
				t.Fatalf("want failure %q; got %s (%v)", test.want, out, err)
			}
		})
	}
}

func TestCheckSysboxServices(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native host command fixture")
	}
	for _, test := range []struct{ name, runtimes, states, want string }{
		{"healthy", "runc\nsysbox-runc\n", "active\nactive\nactive\n", ""},
		{"unregistered", "runc\n", "", "not registered"},
		{"similarly named runtime", "other-sysbox-runc\n", "", "not registered"},
		{"dead component", "sysbox-runc\n", "active\nfailed\nactive\n", "backing Sysbox services are unavailable"},
		{"missing units", "sysbox-runc\n", "unknown\nunknown\nunknown\n", "backing Sysbox services are unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			hostFixtureCommand(t, dir, "docker", `printf '%s' "$TEST_RUNTIMES"`)
			// systemctl is-active succeeds if any of the requested units is active.
			hostFixtureCommand(t, dir, "systemctl", `printf '%s' "$TEST_STATES"`)
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("TEST_RUNTIMES", test.runtimes)
			t.Setenv("TEST_STATES", test.states)
			err := checkSysbox()
			if test.want == "" && err != nil || test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("want %q, got %v", test.want, err)
			}
		})
	}
}
