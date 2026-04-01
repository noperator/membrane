// Tracer implementation inspired by the dyana project:
// https://github.com/dreadnode/dyana/blob/main/dyana/tracer/tracee.py

package membrane

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/term"
)

// Tracer manages a Tracee eBPF sidecar container that traces the agent
// container and writes matching events to a JSONL file.
type Tracer struct {
	containerName string // tracee-<suffix>
	traceFile     string // path to output JSONL file
	cmd           *exec.Cmd
	stdout        io.ReadCloser
	containerID   string        // agent container ID for filtering; set once before streaming starts
	buffered      <-chan string // lines read between ready signal and StartStreaming
	done          chan struct{} // closed when the streaming goroutine exits
}

const traceeImage = "aquasec/tracee:0.24.1"

// traceeEvents is the default set of events to trace.
var traceeEvents = []string{
	"security_file_open",
	"sched_process_exec",
	"security_socket_*",
	"net_packet_dns",
	"signatures",
}

// NewTracer creates a Tracer that will trace the given agent container name
// and write events to traceFile.
func NewTracer(agentContainerName, traceFile string) *Tracer {
	// Reuse the hex suffix from the agent container name (membrane-<hex>).
	suffix := strings.TrimPrefix(agentContainerName, "membrane-")
	return &Tracer{
		containerName: "tracee-" + suffix,
		traceFile:     traceFile,
		done:          make(chan struct{}),
	}
}

// Start launches the Tracee container and blocks until Tracee signals ready
// or the 30-second timeout expires.
func (t *Tracer) Start() error {
	if err := exec.Command("docker", "image", "inspect", traceeImage).Run(); err != nil {
		cmd := exec.Command("docker", "pull", traceeImage)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("pull tracee image: %w", err)
		}
	}

	args := []string{
		"run", "--rm",
		"--name", t.containerName,
		"--privileged",
		"--pid=host",
		// "--cgroupns=host",
		"-v", "/sys/fs/cgroup/system.slice:/sys/fs/cgroup/system.slice:ro",
		"-v", "/etc/os-release:/etc/os-release-host:ro",
		"-e", "LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host",
		"--entrypoint", "/tracee/tracee",
		traceeImage,
		"--output", "json",
		"--log", "debug",
		"--scope", "container=new",
		"--events", strings.Join(traceeEvents, ","),
	}

	t.cmd = exec.Command("docker", args...)

	// Merge stdout and stderr into a single reader via an io.Pipe.
	// Tracee writes the ready signal and log lines to stderr, and JSON
	// events to stdout. We need both in one stream.
	pr, pw := io.Pipe()
	t.cmd.Stdout = pw
	t.cmd.Stderr = pw
	t.stdout = pr

	if err := t.cmd.Start(); err != nil {
		return fmt.Errorf("start tracee: %w", err)
	}

	// Close the pipe writer when the process exits so the reader gets EOF.
	go func() {
		_ = t.cmd.Wait()
		pw.Close()
	}()

	// Wait for the "is ready callback" line or an error/timeout.
	readyCh := make(chan error, 1)
	buffered := make(chan string, 256) // buffer lines read before ready

	go func() {
		scanner := bufio.NewScanner(t.stdout)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "is ready callback") {
				readyCh <- nil
				// Drain remaining lines into the buffered channel so
				// the streaming goroutine can pick them up.
				for scanner.Scan() {
					buffered <- scanner.Text()
				}
				close(buffered)
				return
			}
			if strings.Contains(line, `"L":"FATAL"`) || strings.Contains(line, `"L":"ERROR"`) {
				readyCh <- fmt.Errorf("tracee error during startup: %s", line)
				close(buffered)
				return
			}
		}
		if err := scanner.Err(); err != nil {
			readyCh <- fmt.Errorf("reading tracee output: %w", err)
		} else {
			readyCh <- fmt.Errorf("tracee exited before becoming ready")
		}
		close(buffered)
	}()

	var s *spinner
	if term.IsTerminal(int(os.Stdin.Fd())) {
		s = newSpinner()
		s.Start("Setting up sandbox...")
	}

	select {
	case err := <-readyCh:
		if s != nil {
			s.Stop()
		}
		if err != nil {
			_ = t.cmd.Process.Kill()
			return err
		}
	case <-time.After(30 * time.Second):
		if s != nil {
			s.Stop()
		}
		_ = t.cmd.Process.Kill()
		return fmt.Errorf("tracee did not become ready within 30 seconds")
	}

	t.buffered = buffered
	return nil
}

// StartStreaming sets the agent container ID and starts the background
// goroutine that filters and writes events. Call after Start() returns
// and the container ID is known.
func (t *Tracer) StartStreaming(containerID string) {
	t.containerID = containerID
	go t.streamEvents()
}

// streamEvents reads lines from the buffered channel (lines already read
// after the ready signal), then continues reading from stdout until EOF.
// JSON events whose containerId matches the agent container are written
// to the trace file.
func (t *Tracer) streamEvents() {
	defer close(t.done)

	var f *os.File
	if t.traceFile != "" {
		var err error
		f, err = os.Create(strings.TrimSuffix(t.traceFile, ".gz"))
		if err != nil {
			return
		}
		defer f.Close()
	}

	agentStarted := false

	process := func(line string) {
		if !strings.HasPrefix(line, "{") {
			return
		}

		if !agentStarted {
			var meta struct {
				EventName   string `json:"eventName"`
				ProcessName string `json:"processName"`
			}
			if json.Unmarshal([]byte(line), &meta) == nil &&
				meta.EventName == "sched_process_exec" &&
				meta.ProcessName == "gosu" {
				agentStarted = true
			}
			return
		}

		var ev struct {
			ContainerID string `json:"containerId"`
		}
		if json.Unmarshal([]byte(line), &ev) != nil {
			return
		}
		if ev.ContainerID != t.containerID {
			return
		}
		// TODO: this is where you would add hooks to act on events in real time,
		// e.g. killing the agent container if a suspicious event is detected.
		if f != nil {
			fmt.Fprintln(f, line)
		}
	}

	// Process any lines buffered during the ready-wait phase.
	for line := range t.buffered {
		process(line)
	}

	// Continue reading from stdout until the Tracee container exits.
	scanner := bufio.NewScanner(t.stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		process(scanner.Text())
	}
}

// Stop sends docker stop to the Tracee container and waits for the
// streaming goroutine to finish.
// NOTE: SIGKILL cannot be caught; the tracee container may need manual
// cleanup via: docker stop tracee-<id>
func (t *Tracer) Stop() {
	var s *spinner
	if term.IsTerminal(int(os.Stdin.Fd())) {
		s = newSpinner()
		s.Start("Tearing down sandbox...")
	}

	_ = exec.Command("docker", "stop", "-t", "2", t.containerName).Run()
	if t.containerID != "" {
		<-t.done
	}
	if t.traceFile != "" {
		if err := gzipFile(t.traceFile); err == nil {
			os.Remove(strings.TrimSuffix(t.traceFile, ".gz"))
		}
	}

	if s != nil {
		s.Stop()
	}
}

func gzipFile(dst string) error {
	src := strings.TrimSuffix(dst, ".gz")
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	defer gz.Close()
	_, err = io.Copy(gz, in)
	return err
}
