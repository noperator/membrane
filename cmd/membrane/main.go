package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	flag "github.com/spf13/pflag"

	"github.com/noperator/membrane/pkg/membrane"
)

func main() {
	noUpdate := flag.Bool("no-update", false, "skip checking for updates")
	noTrace := flag.Bool("no-trace", false, "disable Tracee eBPF sidecar")
	noGlobalConfig := flag.Bool("no-global-config", false, "skip reading ~/.membrane/config.yaml (workspace and CLI flags still apply)")
	traceLog := flag.String("trace-log", "", "path for trace log file (default: ~/.membrane/trace/<id>.jsonl.gz)")
	ignore := flag.StringArrayP("ignore", "i", []string{}, "ignore pattern (repeatable)")
	readonly := flag.StringArrayP("readonly", "r", []string{}, "readonly pattern (repeatable)")
	allow := flag.StringArrayP("allow", "a", []string{}, "allow rule: hostname, IP, CIDR, or URL (repeatable)")
	arg := flag.StringArray("arg", []string{}, "extra docker run argument (repeatable)")
	dnsResolver := flag.String("dns-resolver", "", "DNS resolver (overrides config file)")
	sessionIDFile := flag.String("session-id-file", "", "write session ID to this file on startup (for test harnesses)")
	var reset stringFlag
	flag.Var(&reset, "reset", "remove membrane state and exit (c=containers, i=image, d=directory)")
	flag.Lookup("reset").NoOptDefVal = "cid"
	optionFlags := flag.NewFlagSet("", flag.ContinueOnError)
	for _, name := range []string{"no-global-config", "no-trace", "no-update", "reset", "session-id-file", "trace-log"} {
		optionFlags.AddFlag(flag.Lookup(name))
	}
	configFlags := flag.NewFlagSet("", flag.ContinueOnError)
	for _, name := range []string{"ignore", "readonly", "allow", "arg", "dns-resolver"} {
		configFlags.AddFlag(flag.Lookup(name))
	}
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "membrane: Selectively permeable boundary for AI agents.\n\n")
		fmt.Fprintf(os.Stderr, "A lightweight, agent-agnostic, cross-platform sandbox that gives you\n")
		fmt.Fprintf(os.Stderr, "real-time visibility into everything that your agent does.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: membrane [options] [-- command...]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprint(os.Stderr, optionFlags.FlagUsages())
		fmt.Fprintf(os.Stderr, "\nConfig:\n")
		fmt.Fprint(os.Stderr, configFlags.FlagUsages())
	}
	flag.Parse()

	for _, arg := range os.Args[1:] {
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			fmt.Fprintf(os.Stderr, "membrane: unexpected argument %q\n", arg)
			os.Exit(1)
		}
	}

	if isFlagPassed("reset") {
		if err := membrane.Reset(reset.val); err != nil {
			fmt.Fprintf(os.Stderr, "membrane: %v\n", err)
			os.Exit(1)
		}
		return
	}

	cli := membrane.CLIOverrides{
		Ignore:      *ignore,
		Readonly:    *readonly,
		Allow:       *allow,
		Args:        *arg,
		DNSResolver: *dnsResolver,
	}

	if err := membrane.Run(*noUpdate, !*noTrace, *noGlobalConfig, *traceLog, *sessionIDFile, flag.Args(), cli); err != nil {
		var exitErr *membrane.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "membrane: %v\n", err)
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

func (f *stringFlag) String() string     { return f.val }
func (f *stringFlag) Set(v string) error { f.val = v; return nil }
func (f *stringFlag) Type() string       { return "" }
