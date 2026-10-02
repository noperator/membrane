package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestFilesystemPolicyCLI(t *testing.T) {
	if os.Getenv("MEMBRANE_TEST_CLI") == "1" {
		os.Args = append([]string{"membrane"}, os.Args[3:]...)
		main()
		os.Exit(0)
	}
	for _, test := range []struct {
		name string
		args []string
		fail string
	}{
		{"help", []string{"--help"}, ""},
		{"sealed", []string{"--sealed", ".env", "--sealed", "*.pem", "--help"}, ""},
		{"short", []string{"-s", "secrets/", "--help"}, ""},
		{"legacy", []string{"--ignore", ".env", "--help"}, "unknown flag: --ignore"},
		{"legacy-short", []string{"-i", ".env", "--help"}, "unknown shorthand flag: 'i'"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestFilesystemPolicyCLI$", "--"}, test.args...)...)
			cmd.Env = append(os.Environ(), "MEMBRANE_TEST_CLI=1")
			out, err := cmd.CombinedOutput()
			if test.fail != "" {
				if err == nil || !strings.Contains(string(out), test.fail) {
					t.Fatalf("expected %q: err=%v output=%s", test.fail, err, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("CLI failed: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), "-s, --sealed") || strings.Contains(string(out), "--ignore") {
				t.Fatalf("incorrect filesystem policy help:\n%s", out)
			}
		})
	}
}
