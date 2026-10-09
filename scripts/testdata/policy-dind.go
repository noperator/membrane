// Static LSM workload: a scratch-image DinD child needs no package downloads.
package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func denied(err error) {
	if !errors.Is(err, syscall.EACCES) {
		must(fmt.Errorf("expected EACCES, got %v", err))
	}
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "inner" {
		_, err := os.ReadFile("/data/protected")
		denied(err)
		denied(os.WriteFile("/data/protected", []byte("bad"), 0600))
		_, err = os.ReadFile("/data/readonly")
		must(err)
		denied(os.WriteFile("/data/readonly", []byte("bad"), 0600))
		fmt.Println("PASS DinD sealed and readonly inode enforcement")
		return
	}
	deadline := time.Now().Add(30 * time.Second)
	for exec.Command("docker", "info").Run() != nil {
		if time.Now().After(deadline) {
			must(fmt.Errorf("inner Docker readiness timed out"))
		}
		time.Sleep(100 * time.Millisecond)
	}
	path, err := os.Executable()
	must(err)
	data, err := os.ReadFile(path)
	must(err)
	var buf bytes.Buffer
	archive := tar.NewWriter(&buf)
	must(archive.WriteHeader(&tar.Header{Name: "probe", Mode: 0755, Size: int64(len(data))}))
	_, err = archive.Write(data)
	must(err)
	must(archive.Close())
	cmd := exec.Command("docker", "import", "-", "membrane-policy-test")
	cmd.Stdin = &buf
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	must(cmd.Run())
	workspace, err := os.Getwd()
	must(err)
	cmd = exec.Command("docker", "run", "--rm", "--network=none", "-v", workspace+":/data", "membrane-policy-test", "/probe", "inner")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	must(cmd.Run())
}
