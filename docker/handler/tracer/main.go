// Tracer loads custom eBPF probes and streams events as gzipped JSONL.
// Started by the handler entrypoint when tracing is requested.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb probe ../ebpf/probe.c -- -Wall -Werror

package main

import (
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	eventProcessExec   = 1
	eventFileOpen      = 2
	eventSocketConnect = 3
)

type processExecEvent struct {
	Type      string `json:"type"`
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	Timestamp uint64 `json:"timestamp"`
	Comm      string `json:"comm"`
	Argv      string `json:"argv"`
}

type fileOpenEvent struct {
	Type      string `json:"type"`
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	Timestamp uint64 `json:"timestamp"`
	Comm      string `json:"comm"`
	Path      string `json:"path"`
	Flags     uint32 `json:"flags"`
}

type socketConnectEvent struct {
	Type      string `json:"type"`
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	Timestamp uint64 `json:"timestamp"`
	Comm      string `json:"comm"`
	Family    uint16 `json:"family"`
	Daddr     string `json:"daddr"`
	Dport     uint16 `json:"dport"`
}

// cstringAt reads a null-terminated C string from b[offset:offset+maxLen].
func cstringAt(b []byte, offset, maxLen int) string {
	end := offset + maxLen
	if end > len(b) {
		end = len(b)
	}
	s := b[offset:end]
	for i, c := range s {
		if c == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}

// parseEvent parses a raw ringbuf record into a JSON-marshalable value.
//
// C struct layout (natural alignment, 64-bit):
//
//	offset  0: u8   type
//	offset  1: u8   pad[3]
//	offset  4: u32  pid
//	offset  8: u32  ppid
//	offset 12: u32  pad (align u64)
//	offset 16: u64  timestamp
//	offset 24: char comm[16]
//	offset 40: union
//	  process_exec:   argv[256] at 40
//	  file_open:      path[256] at 40, flags(u32) at 296
//	  socket_connect: family(u16) at 40, dport(u16) at 42, daddr[16] at 44
func parseEvent(data []byte) (interface{}, error) {
	if len(data) != 304 {
		return nil, fmt.Errorf("invalid event size: %d bytes", len(data))
	}

	evType := data[0]
	pid := binary.NativeEndian.Uint32(data[4:8])
	ppid := binary.NativeEndian.Uint32(data[8:12])
	ts := binary.NativeEndian.Uint64(data[16:24])
	comm := cstringAt(data, 24, 16)

	const unionOffset = 40

	switch evType {
	case eventProcessExec:
		argv := make([]byte, 0, 256)
		for _, c := range data[unionOffset : unionOffset+256] {
			if c == 0 {
				if len(argv) > 0 {
					argv = append(argv, ' ')
				}
			} else {
				argv = append(argv, c)
			}
		}
		return processExecEvent{
			Type:      "process_exec",
			PID:       pid,
			PPID:      ppid,
			Timestamp: ts,
			Comm:      comm,
			Argv:      strings.TrimRight(string(argv), " "),
		}, nil

	case eventFileOpen:
		flags := binary.NativeEndian.Uint32(data[unionOffset+256 : unionOffset+260])
		return fileOpenEvent{
			Type:      "file_open",
			PID:       pid,
			PPID:      ppid,
			Timestamp: ts,
			Comm:      comm,
			Path:      cstringAt(data, unionOffset, 256),
			Flags:     flags,
		}, nil

	case eventSocketConnect:
		family := binary.NativeEndian.Uint16(data[unionOffset : unionOffset+2])
		dport := binary.NativeEndian.Uint16(data[unionOffset+2 : unionOffset+4])
		daddr := data[unionOffset+4 : unionOffset+20]
		var ip net.IP
		switch family {
		case syscall.AF_INET:
			ip = net.IP(daddr[:net.IPv4len])
		case syscall.AF_INET6:
			ip = net.IP(daddr)
		default:
			return nil, fmt.Errorf("unknown address family: %d", family)
		}
		return socketConnectEvent{
			Type:      "socket_connect",
			PID:       pid,
			PPID:      ppid,
			Timestamp: ts,
			Comm:      comm,
			Family:    family,
			Daddr:     ip.String(),
			Dport:     dport,
		}, nil

	default:
		return nil, fmt.Errorf("unknown event type: %d", evType)
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, os.Getenv("MEMBRANE_TARGET_CGROUP"), os.Getenv("MEMBRANE_TRACE_FILE")); err != nil {
		// All resource and gzip cleanup has run before exiting.
		log.Fatalf("tracer: %+v", err)
	}
	log.Println("tracer exited cleanly")
}

func run(ctx context.Context, cgroupPath, traceFile string) (retErr error) {
	if traceFile == "" {
		return errors.New("MEMBRANE_TRACE_FILE not set")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return fmt.Errorf("tracing requires the host cgroup v2 filesystem: %w", err)
	}

	objs := probeObjects{}
	if err := loadProbeObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	// Session identity is established independently of the event output. Future
	// enforcement programs can share this same map and readiness boundary.
	if cgroupPath == "" {
		return errors.New("MEMBRANE_TARGET_CGROUP not set")
	}
	cgroup, err := os.Open(cgroupPath)
	if err != nil {
		return fmt.Errorf("open session cgroup: %w", err)
	}
	defer cgroup.Close()
	if err := objs.TargetCgroup.Put(uint32(0), uint32(cgroup.Fd())); err != nil {
		return fmt.Errorf("set target cgroup: %w", err)
	}

	var links []link.Link
	closeLinks := func() {
		for _, l := range links {
			l.Close()
		}
		links = nil
	}
	defer closeLinks()
	processExecLink, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceProcessExec, nil)
	if err != nil {
		return fmt.Errorf("attach process_exec tracepoint: %w", err)
	}
	links = append(links, processExecLink)
	fileOpenLink, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceFileOpen})
	if err != nil {
		return fmt.Errorf("attach file_open fentry: %w", err)
	}
	links = append(links, fileOpenLink)
	socketConnectLink, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceSocketConnect, nil)
	if err != nil {
		return fmt.Errorf("attach socket_connect tracepoint: %w", err)
	}
	links = append(links, socketConnectLink)

	if err := os.MkdirAll(filepath.Dir(traceFile), 0o755); err != nil {
		return fmt.Errorf("create trace dir: %w", err)
	}
	f, err := os.Create(traceFile)
	if err != nil {
		return fmt.Errorf("create trace file: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, f.Close()) }()
	gz := gzip.NewWriter(f)
	defer func() { retErr = errors.Join(retErr, gz.Close()) }()
	enc := json.NewEncoder(gz)

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ringbuf reader: %w", err)
	}
	defer rd.Close()

	if err := ctx.Err(); err != nil {
		return err
	}
	log.Printf("tracing cgroup subtree %s to %s", cgroup.Name(), traceFile)
	const readyFile = "/tmp/tracer-ready"
	if err := os.WriteFile(readyFile, nil, 0o644); err != nil {
		return fmt.Errorf("signal scoped BPF readiness: %w", err)
	}
	defer os.Remove(readyFile)

	draining := false
	for {
		if ctx.Err() != nil && !draining {
			// Stop producers, then drain queued events before closing gzip.
			closeLinks()
			if err := rd.Flush(); err != nil {
				return fmt.Errorf("flush ringbuf: %w", err)
			}
			draining = true
		}
		rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
		record, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if errors.Is(err, ringbuf.ErrFlushed) && draining {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read ringbuf: %w", err)
		}
		ev, err := parseEvent(record.RawSample)
		if err != nil {
			return fmt.Errorf("decode event: %w", err)
		}
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("write trace event: %w", err)
		}
	}
}
