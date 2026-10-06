package main

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

// Compile success alone is insufficient: clang can emit libc calls which
// cannot be resolved when loading a BPF program (for example, memcmp).
func TestGeneratedProgramReferences(t *testing.T) {
	for _, load := range []func() (*ebpf.CollectionSpec, error){loadProbe, loadPolicy} {
		spec, err := load()
		if err != nil {
			t.Fatal(err)
		}
		for name, program := range spec.Programs {
			symbols, err := program.Instructions.SymbolOffsets()
			if err != nil {
				t.Fatal(err)
			}
			for _, reference := range program.Instructions.FunctionReferences() {
				if _, ok := symbols[reference]; !ok {
					t.Errorf("%s: unresolved BPF function %q", name, reference)
				}
			}
		}
	}
}

func TestParseSocketConnectEvent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		family uint16
		addr   string
	}{
		{name: "IPv4", family: syscall.AF_INET, addr: "203.0.113.7"},
		{name: "IPv6", family: syscall.AF_INET6, addr: "2001:db8::7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, 304)
			data[0] = eventSocketConnect
			binary.NativeEndian.PutUint32(data[4:8], 123)
			binary.NativeEndian.PutUint32(data[8:12], 45)
			binary.NativeEndian.PutUint64(data[16:24], 678)
			copy(data[24:40], "curl")
			binary.NativeEndian.PutUint16(data[40:42], tc.family)
			binary.NativeEndian.PutUint16(data[42:44], 443)
			ip := net.ParseIP(tc.addr)
			if tc.family == syscall.AF_INET {
				ip = ip.To4()
			}
			copy(data[44:60], ip)

			got, err := parseEvent(data)
			if err != nil {
				t.Fatalf("parseEvent: %v", err)
			}
			event, ok := got.(socketConnectEvent)
			if !ok {
				t.Fatalf("parseEvent returned %T, want socketConnectEvent", got)
			}
			if event.Type != "socket_connect" || event.Family != tc.family || event.Daddr != tc.addr || event.Dport != 443 {
				t.Errorf("socket_connect event = %+v, want type=socket_connect family=%d daddr=%s dport=443", event, tc.family, tc.addr)
			}
			if event.PID != 123 || event.PPID != 45 || event.Timestamp != 678 || event.Comm != "curl" {
				t.Errorf("event metadata = %+v", event)
			}
		})
	}
}

func TestParseProcessExecAndFileOpen(t *testing.T) {
	data := make([]byte, 304)
	data[0] = eventProcessExec
	copy(data[40:], "sh\x00-c\x00echo hello\x00")
	got, err := parseEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if e := got.(processExecEvent); e.Type != "process_exec" || e.Argv != "sh -c echo hello" {
		t.Fatalf("process_exec = %+v", e)
	}
	data = make([]byte, 304)
	data[0] = eventFileOpen
	copy(data[40:], "/tmp/outside-workspace")
	binary.NativeEndian.PutUint32(data[296:], 0101)
	got, err = parseEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if e := got.(fileOpenEvent); e.Type != "file_open" || e.Path != "/tmp/outside-workspace" || e.Flags != 0101 {
		t.Fatalf("file_open = %+v", e)
	}
}

func TestRejectMalformedEvents(t *testing.T) {
	if _, err := parseEvent([]byte{eventProcessExec}); err == nil {
		t.Fatal("accepted truncated record")
	}
	data := make([]byte, 304)
	if _, err := parseEvent(data); err == nil {
		t.Fatal("accepted unknown event type")
	}
}
