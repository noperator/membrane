package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	flag "github.com/spf13/pflag"

	"github.com/noperator/cagent/pkg/cagent"
)

func main() {
	noUpdate := flag.Bool("no-update", false, "skip checking for updates")
	trace := flag.Bool("trace", false, "enable Tracee eBPF sidecar")
	var traceLog stringOptFlag
	flag.Var(&traceLog, "trace-log", "write trace events to a file; defaults to ~/.cagent/trace/<id>.jsonl")
	flag.Lookup("trace-log").NoOptDefVal = "file"
	var reset stringFlag
	flag.Var(&reset, "reset", "remove cagent state and exit (c=containers, i=image, v=volume, d=directory)")
	flag.Lookup("reset").NoOptDefVal = "civd"
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "cagent: Agent in a cage.\n\n")
		fmt.Fprintf(os.Stderr, "Locks down the network and filesystem so an agent is free to explore\n")
		fmt.Fprintf(os.Stderr, "the mounted workspace while reducing the risk of it going off the rails.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: cagent [options] [-- command...]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	for _, arg := range os.Args[1:] {
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			fmt.Fprintf(os.Stderr, "cagent: unexpected argument %q\n", arg)
			os.Exit(1)
		}
	}

	if isFlagPassed("reset") {
		if err := cagent.Reset(reset.val); err != nil {
			fmt.Fprintf(os.Stderr, "cagent: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := cagent.Run(*noUpdate, *trace, traceLog.val, flag.Args()); err != nil {
		var exitErr *cagent.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "cagent: %v\n", err)
		os.Exit(1)
	}
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// stringFlag implements pflag.Value with a custom Type() for help output.
type stringFlag struct{ val string }

func (f *stringFlag) String() string { return f.val }
func (f *stringFlag) Set(v string) error { f.val = v; return nil }
func (f *stringFlag) Type() string { return "" }

// stringOptFlag implements pflag.Value for optional-value string flags.
type stringOptFlag struct{ val string }

func (f *stringOptFlag) String() string { return f.val }
func (f *stringOptFlag) Set(v string) error { f.val = v; return nil }
func (f *stringOptFlag) Type() string { return "" }
