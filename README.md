<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="img/logo-dark-4.png">
    <img alt="logo" src="img/logo-light-4.png" width="500px">
  </picture>
  <br>
  Selectively permeable boundary for AI agents.
</p>

## Description

Membrane is a lightweight, agent-agnostic, cross-platform sandbox that gives you real-time visibility into everything that your agent does.

The most important property of a secure sandbox is that you can clearly understand what it's doing. As it gets bigger and more complex, it introduces more potential failure points. Membrane is deliberately minimal. It covers the core features you'd expect from an agent sandbox (namely, network and filesystem isolation) and omits everything else. At the time of this writing, **Membrane has about 1% as many lines of code as [OpenShell](https://github.com/NVIDIA/OpenShell)**. Simplicity is a feature.

```text
$ tokei -o json membrane/  | jq .Total.code
6727

$ tokei -o json OpenShell/ | jq .Total.code
659714
```

### Features

- **Network egress filtering**: Allowed hosts, ports, HTTP methods, and HTTP paths are enforced via firewall/proxy.<br><sub>&emsp;*Most tools don't filter the network at all, or require manual iptables rules that are easy to misconfigure.*</sub>
- **Filesystem isolation**: Sensitive files can be masked and made invisible to the agent, or mounted read-only.<br><sub>&emsp;*Most tools offer no granular filesystem controls on top of bind mounts.*</sub>
- **Observability**: eBPF traces all agent filesystem, network, and process activity at the kernel level.<br><sub>&emsp;*Most tools offer no runtime visibility into what the agent is actually doing.*</sub>
- **Nested containers**: Docker-in-Docker via unprivileged Sysbox containers.<br><sub>&emsp;*Most tools require `--privileged` (unsafe) or a separate hypervisor.*</sub>
- **Agent-agnostic**: Wraps any process or command, not coupled to a specific agent.<br><sub>&emsp;*Most tools are tightly coupled to a specific agent (Claude Code, Codex, etc.).*</sub>
- **Cross-platform**: Linux and macOS via Docker; strong enforcement on both platforms.<br><sub>&emsp;*Most tools rely on OS-specific primitives: Landlock and bubblewrap (Linux), Seatbelt and Apple Containers (macOS).*</sub>
- **Lightweight**: Container-based, near-zero startup overhead on top of Docker.<br><sub>&emsp;*Most tools that offer kernel-level isolation do so at the expense of requiring a full hypervisor.*</sub>
- **Unix-native**: Use with shell pipelines, GNU parallel, or script it however you want.<br><sub>&emsp;*Most tools target IDE-attached environments that are awkward to drive programmatically.*</sub>

## Getting started

### Prerequisites

Membrane has been tested on macOS and Ubuntu Linux. The Linux Docker host must use cgroup v2 and have BPF LSM active. On **macOS**, [Homebrew](https://brew.sh) must be installed; Membrane runs in a dedicated [Colima](https://github.com/abiosoft/colima) VM that provides the Linux kernel. On **Linux**, [Docker Engine](https://docs.docker.com/engine/install/ubuntu/) must be installed; the first-run setup configures BPF LSM when supported and installs Sysbox on top of the existing Docker installation.

### Install

```bash
go install github.com/noperator/membrane/cmd/membrane@latest
```

<details><summary>Initial setup</summary>

On first run, membrane checks that its host prerequisites are present and healthy (or otherwise offers to configure them). It then clones the repo to `~/.membrane/src/`, builds the `membrane-agent` and `membrane-handler` Docker images, and writes a default config to `~/.membrane/config.yaml`. Subsequent runs check for updates automatically. Initial install takes about 2 minutes.

On **macOS**, membrane runs inside a dedicated [Colima](https://github.com/abiosoft/colima) VM with [Sysbox](https://github.com/nestybox/sysbox) installed. If needed, membrane offers to run [`scripts/install-macos.sh`](scripts/install-macos.sh), which installs the host tools, creates/configures the dedicated VM, activates BPF LSM in its Linux kernel, installs Sysbox, and makes its backing services persistent across VM restarts. The dedicated Colima profile keeps membrane's containers and images isolated from your existing Docker setup.

On **Linux**, membrane uses the system Docker daemon directly. If setup is incomplete, membrane offers to run [`scripts/install-linux.sh`](scripts/install-linux.sh), which activates BPF LSM when supported and installs, registers, enables, and verifies Sysbox. Enabling BPF LSM can require a GRUB update and reboot; membrane asks before changing native Linux boot configuration.

</details>

### Usage

```
membrane -h

Usage: membrane [options] [-- command...]

Options:
      --no-global-config         skip reading ~/.membrane/config.yaml (workspace and CLI flags still apply)
      --no-trace                 disable eBPF tracing
      --no-update                skip checking for updates
      --reset[=cid]              remove membrane state and exit (c=containers, i=image, d=directory)
      --session-id-file string   write session ID to this file on startup (for test harnesses)
      --trace-log string         path for trace log file (default: ~/.membrane/trace/<id>.jsonl.gz)

Config:
  -a, --allow stringArray      allow rule: hostname, IP, CIDR, or URL (repeatable)
      --arg stringArray        extra docker run argument (repeatable)
      --dns-resolver string    DNS resolver (overrides config file)
  -s, --sealed stringArray     sealed pattern (repeatable)
  -r, --readonly stringArray   readonly pattern (repeatable)
```

Optionally pass a specific command to be executed, using `--` to separate membrane options from the command to run inside the container.

```bash
# Drop into a shell
cd /your/workspace
membrane

# Run a specific command
membrane -- claude -p "just say hello"
membrane -- bash -c "echo hello"
```

#### Non-interactive mode

When stdin is not a terminal, membrane automatically skips PTY allocation and wires stdin/stdout/stderr directly. This lets you pipe input, capture output, and use membrane in scripts or tools like GNU parallel.

```bash
# Pipe input
echo 'Today is my birthday, but no one noticed.' |
    membrane -- claude -p 'Tell me something nice.'

Happy birthday! 🎂

# Capture output to a file
echo 'target char count: 20' |
    membrane -- claude -p 'Output something that matches the exact target character count and nothing more.' |
    tee /dev/stderr | tr -d '\n' | wc -c

This is twenty chars
      20
```

<details><summary>Advanced usage</summary>

#### Modify the images

If you want to customize the Dockerfiles, firewall rules, or entrypoints, edit the files in `~/.membrane/src/` and rebuild:

```bash
docker build -t membrane-agent ~/.membrane/src/docker/agent/
docker build -t membrane-handler ~/.membrane/src/docker/handler/
```

If you've made local edits and an update is available, membrane will back up `~/.membrane/src/` to a timestamped directory before pulling.

#### Reset

`membrane --reset` will remove running containers, the Docker images, and `~/.membrane/`. Workspace `.membrane.yaml` files are not affected. You can also reset individual components:

```bash
membrane --reset=cid   # all
membrane --reset=ci    # containers and images only
```

### Trace execution

By default, membrane records an eBPF trace of process executions, file opens, and network connection attempts across the agent's complete workload cgroup, including nested containers.

Membrane creates the workload cgroup and installs and scopes the eBPF probes before starting any workload code. If required probes or filesystem policy cannot be loaded or attached, setup fails before the workload starts.

In this example, I just tell Codex to go download the homepage of my blog.

```bash
membrane --trace-log=blog.jsonl.gz -- \
    codex exec --dangerously-bypass-approvals-and-sandbox \
    'Download the homepage of my blog noperator.dev and save it to blog.html.'
```

Codex uses curl to download the page and saves it to `/workspace/blog.html`.

The raw trace is intentionally comprehensive, so we can use a reproducible jq filter to show the commands Codex launches to carry out its actions, along with their workspace file activity and network connections:

```bash
𝄢 gzip -dc blog.jsonl.gz | jq -rs '
  sort_by(.timestamp) as $e |

  # Find the Codex process(es).
  [$e[]
    | select(.type == "process_exec" and .comm == "codex")
    | .pid
  ] | unique as $codex_pids |

  # Find real shell commands launched directly by Codex, excluding its
  # shell-snapshot/setup machinery. Record when each command actually starts.
  (reduce (
    $e[]
    | select(
        .type == "process_exec"
        and .comm == "bash"
        and (.argv | startswith("/bin/bash -c "))
        and ((.argv | contains("CODEX_")) | not)
        and ((.argv | contains("/.codex/shell_snapshots/")) | not)
      )
    | select(.ppid as $p | $codex_pids | index($p))
  ) as $x (
    {};
    .[$x.pid | tostring] = $x.timestamp
  )) as $starts |

  # Show activity attributable to those commands after they start.
  $e[]
  | select(
      ($starts[.pid | tostring] // null) as $start
      | $start != null and .timestamp >= $start
    )
  | select(
      .type == "process_exec"
      or .type == "socket_connect"
      or (
        .type == "file_open"
        and (.path | startswith("/workspace"))
      )
    )

  | if .type == "process_exec" then
      "exec  \(.comm): \(.argv)"
    elif .type == "file_open" then
      "file  \(.comm): flags=\(.flags) \(.path)"
    elif .type == "socket_connect" then
      "conn  \(.comm): \(if .family == 2 then \"AF_INET\" elif .family == 10 then \"AF_INET6\" else \"AF_\(.family)\" end) \(.daddr):\(.dport)"
    else
      empty
    end
'
```

We see that Codex launches curl, curl resolves and connects to the site, opens `/workspace/blog.html` for writing, and Codex verifies the result.

```text
exec  bash: /bin/bash -c curl --fail --location --silent --show-error https://noperator.dev/ --output blog.html
exec  curl: curl --fail --location --silent --show-error https://noperator.dev/ --output blog.html
conn  curl: AF_INET 172.18.0.2:53
conn  curl: AF_INET6 2606:4700:3034::ac43:a3fd:443
conn  curl: AF_INET6 2606:4700:3030::6815:5b07:443
conn  curl: AF_INET 172.67.163.253:443
conn  curl: AF_INET 104.21.91.7:443
conn  curl: AF_INET 172.67.163.253:443
file  curl: flags=131649 /workspace/blog.html
exec  bash: /bin/bash -c ls -lh blog.html
exec  ls: ls -lh blog.html
```

</details>

### Configure

Configuration is YAML and works at two levels:

- **Global** (`~/.membrane/config.yaml`): Applies to every workspace. Written from the default template on first run. Edit this to set your baseline allow and deny lists, sealed patterns, and readonly patterns.
- **Workspace** (`.membrane.yaml` in your project root): Applies to the current workspace only. Lists in the workspace config are appended to the global config, not replaced.

```yaml
# For both `sealed` and `readonly` below: These filesystem policies are based
# on a startup *snapshot*. Selectors (e.g., a path like `.env`) are evaluated
# before workload code runs against objects that already exist. An enrolled
# object remains protected if it is renamed; a newly created or replacement
# inode is not automatically enrolled just because its pathname matches a
# selector.

# `sealed` paths remain visible (e.g., `stat` still works), but file contents
# cannot be read or modified.
sealed:
  - secrets/
  - "*.pem"

# `readonly` paths may have their contents read, but cannot be modified.
readonly:
  - config/

# `allow` lists what the agent is allowed to reach. Each entry is
# auto-detected from its value: hostname, IP, CIDR, or URL. Object
# form supports additional constraints via ports: and http: keys.
allow:
  # 1. Plain hostname: any TCP port, any HTTP method/path.
  # UDP is blocked unless explicitly opted in (see example 8).
  - github.com

  # 2. Hostname with port restriction: TCP port 443 only (bare port
  # numbers default to TCP). Other ports blocked at L3.
  - dest: registry.mycompany.com
    ports: [443]

  # 3. Hostname with http rules: HTTP/HTTPS only, method/path enforced
  # on any TCP port. Non-HTTP TCP (SSH, etc.) is blocked. mitmproxy
  # detects HTTP/TLS from protocol bytes, not port number, so this
  # works on 8443, 8080, or any other port the agent connects to.
  - dest: api.anthropic.com
    http:
      - methods: [POST]
        paths:
          - /v1/messages

  # 4. Hostname with http rules AND explicit TCP port. The two entries
  # are independent. HTTP is enforced on all TCP ports; port 22
  # also allowed. Other non-HTTP TCP ports are blocked.
  - dest: github.com
    http:
      - methods: [GET, POST]
        paths: [/api]
  - dest: github.com   # second entry adds port 22
    ports: [22/tcp]

  # 5. URL entry: shorthand for hostname + port from scheme + path
  # prefix. All methods allowed at /v1 and its descendants.
  - https://api.openai.com/v1

  # 6. URL entry with http rules: the most specific form. Port from
  # scheme enforced at L3, method and path enforced at L7.
  - dest: https://api.example.com/v1
    http:
      - methods: [POST]
        paths:
          - messages    # relative: resolves to /v1/messages
          - /v1/models  # absolute path also works

  # 7. IP and CIDR: bypass DNS, added directly to firewall. Without
  # http, any TCP is allowed. With http, same L7 enforcement as
  # hostname entries: non-HTTP TCP blocked, UDP always blocked.
  - 192.168.2.1
  - dest: 192.168.3.0/24
    http:
      - methods: [GET]
        paths: [/api]

  # 8. UDP opt-in: bare port numbers default to TCP. Append /udp to
  # explicitly allow UDP on a specific port.
  - dest: 8.8.8.8
    ports: [53/udp]

  # 9. Host pattern wildcard: `*` must be a full DNS label. Matches
  # any immediate subdomain of github.com (api.github.com,
  # objects.github.com, etc.) but NOT the apex github.com itself.
  - "*.github.com"

  # 10. Any host: bare `*` allows any destination. Use with caution.
  # Here: GET requests to any host, on any TCP port, over HTTP or
  # HTTPS. Non-HTTP TCP and UDP still blocked.
  - dest: "*"
    http:
      - methods: [GET]

# `args` lists raw arguments appended when creating the agent container.
# Environment variables are expanded ($VAR, ${VAR}). Each flag and
# its argument must be separate items. Treat this as trusted host-level
# configuration, especially in a workspace .membrane.yaml.
args:
  - -e
  - MY_API_KEY=abc123
  - -v
  - $HOME/.aws:/home/agent/.aws:ro
  - -e
  - AWS_PROFILE=myprofile

# Block DELETE at /api and its descendants, overriding the github.com allow.
# Query strings do not affect path matching.
deny:
  - dest: https://github.com
    http:
      - methods: [DELETE]
        paths: [/api]
```

See [`config-default.yaml`](config-default.yaml) for the full default allow list.

### Troubleshooting

- **Connections fail silently when `br_netfilter` kernel module is loaded on the host.** Bridge traffic gets routed through iptables and dropped by Docker's `DOCKER-ISOLATION-STAGE-1` chain. Membrane tries to work around it by injecting a `DOCKER-USER` rule (requires `sudo`); if that fails, upgrade Docker to 27.3.1+ and reboot to unload the module cleanly.

## Back matter

### See also

- https://github.com/trailofbits/claude-code-devcontainer
- https://github.com/RchGrav/claudebox
- https://github.com/anthropics/claude-code/tree/main/.devcontainer
- https://www.anthropic.com/engineering/claude-code-sandboxing

### To-do

- [ ] support Docker checkpoint
- [ ] optimize startup/teardown time
- [ ] per-session home dir overlay
- [ ] support trusting specific CA certs
- [ ] return error messages from proxy
- [ ] add debug flag
- [ ] BYO container
- [ ] require explicit trust/approval for workspace `.membrane.yaml`

<details><summary>Completed</summary>

- [x] replace Tracee sidecar with built-in eBPF probes
- [x] support wildcard hostnames
- [x] support HTTP filters on IP dest
- [x] detect HTTP(S) via bytes vs ports
- [x] support Docker-in-Docker on macOS
- [x] whitelist HTTPS paths/endpoints with L7 method/path filtering
- [x] pass config via CLI (in addition to file)
- [x] whitelist IPs and CIDRs
- [x] set custom DNS resolver
- [x] mount agent home dir as ~/.membrane/home on host
- [x] monitor agent with eBPF
- [x] specify allow rules at runtime
- [x] git-aware read-only mounts
- [x] refresh firewall on DNS resolution (dns-proxy)
- [x] quiet down logging a bit
- [x] make sealed/readonly configurable
- [x] allow reading from host stdin (to be used in pipeline)
- [x] auto-install prerequisites on first run

</details>
