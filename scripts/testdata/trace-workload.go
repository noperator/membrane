// A static workload for outer and scratch-image inner Docker tracing tests.
// Using the same binary in DinD avoids registry/network dependencies.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func command(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c
}

func connect(family, port int, loopback bool) bool {
	fd, err := syscall.Socket(family, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)
	var addr syscall.Sockaddr
	if family == syscall.AF_INET {
		ip := [4]byte{198, 51, 100, 7}
		if loopback {
			ip = [4]byte{127, 0, 0, 1}
		}
		addr = &syscall.SockaddrInet4{Port: port, Addr: ip}
	} else {
		ip := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}
		if loopback {
			ip = [16]byte{15: 1}
		}
		addr = &syscall.SockaddrInet6{Port: port, Addr: ip}
	}
	// A connect attempt is enough; no external service or route is required.
	_ = syscall.Connect(fd, addr)
	return true
}

func main() {
	token := os.Args[1]
	port, err := strconv.Atoi(os.Args[2])
	must(err)
	must(os.MkdirAll("/tmp", 0o755))
	// No initial delay: this open and this process's exec must be captured.
	must(os.WriteFile("/tmp/"+token+".write", []byte("first"), 0o644))
	if len(os.Args) > 3 && (os.Args[3] == "hold" || os.Args[3] == "tty") {
		must(os.WriteFile("/workspace/"+token+".first", nil, 0o644))
		if os.Args[3] == "tty" {
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			must(err)
			fmt.Print("TTY INPUT ", line)
			// Default SIGINT handling exits with 130 when Ctrl-C reaches us.
			for {
				time.Sleep(time.Second)
			}
		}
		deadline := time.Now().Add(90 * time.Second)
		for {
			if _, err := os.Stat("/workspace/continue"); err == nil {
				break
			}
			if time.Now().After(deadline) {
				must(fmt.Errorf("test barrier timed out"))
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	_, err = os.ReadFile("/etc/hostname")
	must(err)
	if !connect(syscall.AF_INET, port, false) {
		must(fmt.Errorf("IPv4 socket unavailable"))
	}
	connect(syscall.AF_INET, port+10, true)
	v6 := connect(syscall.AF_INET6, port, false)
	connect(syscall.AF_INET6, port+10, true)
	if v6 {
		fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, 0)
		must(err)
		_ = syscall.Connect(fd, &syscall.SockaddrInet6{
			Port: port + 10, Addr: [16]byte{10: 0xff, 11: 0xff, 12: 127, 15: 1},
		})
		must(syscall.Close(fd))
	}
	fmt.Printf("IPV6 %s %t\n", token, v6)

	if len(os.Args) > 4 && os.Args[4] == "dind" {
		// The outer entrypoint starts dockerd. Wait for API readiness too.
		deadline := time.Now().Add(20 * time.Second)
		for exec.Command("docker", "info").Run() != nil {
			if time.Now().After(deadline) {
				must(fmt.Errorf("DinD daemon not ready"))
			}
			time.Sleep(100 * time.Millisecond)
		}
		self, err := os.Executable()
		must(err)
		binary, err := os.ReadFile(self)
		must(err)
		var archive bytes.Buffer
		tw := tar.NewWriter(&archive)
		must(tw.WriteHeader(&tar.Header{Name: "probe", Mode: 0o755, Size: int64(len(binary))}))
		_, err = tw.Write(binary)
		must(err)
		must(tw.Close())
		image := "membrane-trace-test:" + token
		importCmd := command("docker", "import", "-", image)
		importCmd.Stdin = &archive
		must(importCmd.Run())
		must(command("docker", "run", "--rm", image, "/probe", "inner-"+token, strconv.Itoa(port+100)).Run())
		must(command("docker", "rmi", image).Run())
		fmt.Println("DIND", token, "ok")
	}
}
