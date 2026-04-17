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

The most important property of a secure sandbox is that you can clearly understand what it's doing. As it gets bigger and more complex, it introduces more potential failure points. Membrane is deliberately minimal. It covers the core features you'd expect from an agent sandbox (namely, network and filesystem isolation) and omits everything else. At the time of this writing, **membrane's codebase is 50X smaller than [OpenShell](https://github.com/NVIDIA/OpenShell)**, or about 2% the size. Simplicity is a feature.

```
$ find OpenShell/ -name '*.rs' -exec cat {} \; | wc -c
 2833412
$ find membrane/ -name '*.go' -exec cat {} \; | wc -c
   55689
$ echo 2833412 / 55689 | bc -l
50.88
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

Membrane has been tested on macOS and Ubuntu Linux. On **macOS**, [Homebrew](https://brew.sh) must be installed for the first-run install script to install Colima and Docker CLI (if needed). On **Linux**, [Docker Engine](https://docs.docker.com/engine/install/ubuntu/) must be installed and running; the first-run install script installs Sysbox on top of an existing Docker installation.

### Install

```bash
go install github.com/noperator/membrane/cmd/membrane@latest
```

<details><summary>Initial setup</summary>

On first run, membrane checks that all dependencies are present (or otherwise offers to install them). It then clones the repo to `~/.membrane/src/`, builds the `membrane-agent` and `membrane-handler` Docker images, and writes a default config to `~/.membrane/config.yaml`. Subsequent runs check for updates automatically. Initial install takes about 5 minutes.

On **macOS**, membrane runs inside a dedicated [Colima](https://github.com/abiosoft/colima) VM with [Sysbox](https://github.com/nestybox/sysbox) installed. If these aren't present, membrane will offer to run [`scripts/install-macos.sh`](scripts/install-macos.sh) which installs Colima and Docker CLI via Homebrew, creates a dedicated Colima VM, and installs Sysbox inside the VM and registers it as a Docker runtime. The dedicated Colima profile keeps membrane's containers and images isolated from your existing Docker setup.

On **Linux**, membrane uses the system Docker daemon directly. If Sysbox isn't installed, membrane will offer to run [`scripts/install-linux.sh`](scripts/install-linux.sh) which installs and registers it automatically.

</details>

### Usage

```
membrane -h

Usage: membrane [options] [-- command...]

Options:
      --no-global-config         skip reading ~/.membrane/config.yaml (workspace and CLI flags still apply)
      --no-trace                 disable Tracee eBPF sidecar
      --no-update                skip checking for updates
      --reset[=cid]              remove membrane state and exit (c=containers, i=image, d=directory)
      --session-id-file string   write session ID to this file on startup (for test harnesses)
      --trace-log string         path for trace log file (default: ~/.membrane/trace/<id>.jsonl.gz)

Config:
  -a, --allow stringArray      allow rule: hostname, IP, CIDR, or URL (repeatable)
      --arg stringArray        extra docker run argument (repeatable)
      --dns-resolver string    DNS resolver (overrides config file)
  -i, --ignore stringArray     ignore pattern (repeatable)
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

By default, membrane records an eBPF trace of everything the agent does. In this example, I just tell Claude to go download the homepage of my blog.

```bash
membrane --trace-log=blog.jsonl -- \
    claude --dangerously-skip-permissions \
    -p 'Download the homepage of my blog noperator.dev and save it to blog.html.'

Done — saved the homepage to `/workspace/blog.html` (16,927 bytes).
```

Now we can look at the eBPF trace with jq and grep to show the full story of what Claude did in the container:

```bash
𝄢 jq -rs '
  sort_by(.timestamp) |
  (map(select(.processName == "gosu")) | last | .timestamp) as $t |
  .[] | select(.timestamp > $t) |
  if .eventName == "sched_process_exec" then
    "exec  \(.processName): \(.args[] | select(.name == "argv") | .value | join(" "))"
  elif .eventName == "net_packet_dns" and ((.args[] | select(.name == "metadata") | .value.direction) == 2) then
    "dns   \(.processName) → \(.args[] | select(.name == "proto_dns") | .value.questions[0] | "\(.name) \(.type)")"
  elif .eventName == "security_file_open" then
    "file  \(.processName): \(.args[] | select(.name == "flags") | .value) \(.args[] | select(.name == "pathname") | .value)"
  elif .eventName == "security_socket_connect" then
    "conn  \(.processName): \(.args[] | select(.name == "remote_addr") | .value | "\(.sa_family) \(.sin_addr // .sin6_addr // .sun_path):\(.sin_port // .sin6_port // "")")"
  else empty end
' blog.jsonl | grep -vE '^file.* /(usr|dev|etc|proc|sys|run|home|workspace/\.git|tmp/claude)|^conn.* /var|^\s|^$| git(-remote-http)?:'
```

eBPF can be pretty noisy and there's a lot to analyze here, but the main gist of what we see is:
- the agent is given the initial prompt
- it explores the filesystem to see which tools are available
- finally it uses curl to save the blog homepage to disk

<details><summary>Full trace</summary>

```
exec  claude: /usr/bin/env node /usr/bin/claude --dangerously-skip-permissions -p Download the homepage of my blog noperator.dev and save it to blog.html.
exec  node: node /usr/bin/claude --dangerously-skip-permissions -p Download the homepage of my blog noperator.dev and save it to blog.html.
conn  node: AF_INET 8.8.8.8:53
dns   node → api.anthropic.com A
conn  node: AF_INET 8.8.8.8:53
dns   node → api.anthropic.com A
exec  sh: /bin/sh -c which npm
exec  sh: /bin/sh -c which bun
exec  sh: /bin/sh -c which yarn
exec  sh: /bin/sh -c which deno
exec  sh: /bin/sh -c which pnpm
conn  claude: AF_INET 160.79.104.10:443
exec  sh: /bin/sh -c which node
conn  node: AF_INET 8.8.8.8:53
dns   node → api.anthropic.com A
conn  node: AF_INET 8.8.8.8:53
dns   node → api.anthropic.com A
conn  claude: AF_INET 160.79.104.10:443
file  node: 149504 /workspace
conn  claude: AF_INET 160.79.104.10:443
conn  claude: AF_INET 160.79.104.10:443
conn  node: AF_INET 8.8.8.8:53
dns   node → api.anthropic.com A
conn  claude: AF_INET 160.79.104.10:443
exec  sh: /bin/sh -c which git
exec  rg: /usr/lib/node_modules/@anthropic-ai/claude-code/vendor/ripgrep/arm64-linux/rg --version
exec  rg: /usr/lib/node_modules/@anthropic-ai/claude-code/vendor/ripgrep/arm64-linux/rg --files --hidden /workspace
file  rg: 147456 /workspace
file  rg: 147456 /workspace/pkg
file  rg: 147456 /workspace/test
file  rg: 147456 /workspace/pkg/membrane
file  rg: 147456 /workspace/img
file  rg: 147456 /workspace/cmd
file  rg: 147456 /workspace/cmd/membrane
exec  sh: /bin/sh -c ps aux | grep -E "code|cursor|windsurf|idea|pycharm|webstorm|phpstorm|rubymine|clion|goland|rider|datagrip|dataspell|aqua|gateway|fleet|android-studio" | grep -v grep
exec  grep: grep -E code|cursor|windsurf|idea|pycharm|webstorm|phpstorm|rubymine|clion|goland|rider|datagrip|dataspell|aqua|gateway|fleet|android-studio
exec  ps: ps aux
exec  grep: grep -v grep
dns   git-remote-http → github.com A
dns   git-remote-http → github.com AAAA
exec  which: /bin/sh /usr/bin/which /usr/lib/node_modules/@anthropic-ai/claude-code/vendor/ripgrep/arm64-linux/rg
exec  which: /bin/sh /usr/bin/which bwrap
exec  which: /bin/sh /usr/bin/which socat
exec  sh: /bin/sh -c npm root -g
exec  npm: /usr/bin/env node /usr/bin/npm root -g
exec  node: node /usr/bin/npm root -g
exec  uname: uname -sr
exec  sh: /bin/sh -c which zsh
exec  sh: /bin/sh -c which bash
exec  bash: /bin/bash -c -l SNAPSHOT_FILE=/home/agent/.claude/shell-snapshots/snapshot-bash-1772485556640-5hbuui.sh
exec  locale-check: /usr/bin/locale-check C.UTF-8
exec  cut: cut -d  -f3
exec  grep: grep -vE ^_[^_]
exec  head: head -n 1000
exec  awk: awk {print "set -o " $1}
exec  head: head -n 1000
exec  grep: grep on
exec  sed: sed s/^alias //g
exec  sed: sed s/^/alias -- /
exec  head: head -n 1000
exec  bash: /bin/bash -c source /home/agent/.claude/shell-snapshots/snapshot-bash-1772485556640-5hbuui.sh && shopt -u extglob 2>/dev/null || true && eval 'curl -sL -o /workspace/blog.html https://noperator.dev' \< /dev/null && pwd -P >| /tmp/claude-cca8-cwd
exec  curl: curl -sL -o /workspace/blog.html https://noperator.dev
conn  curl: AF_INET 8.8.8.8:53
dns   curl → noperator.dev A
dns   curl → noperator.dev AAAA
conn  curl: AF_INET 104.21.91.7:443
conn  curl: AF_INET 172.67.163.253:443
conn  curl: AF_INET6 2606:4700:3037::ac43:a3fd:443
conn  curl: AF_INET6 2606:4700:3035::6815:5b07:443
conn  curl: AF_INET 104.21.91.7:443
conn  node: AF_INET 8.8.8.8:53
dns   node → api.anthropic.com A
conn  claude: AF_INET 160.79.104.10:443
file  node: 131072 /workspace/blog.html
exec  bash: /bin/bash -c source /home/agent/.claude/shell-snapshots/snapshot-bash-1772485556640-5hbuui.sh && shopt -u extglob 2>/dev/null || true && eval 'wc -c /workspace/blog.html && head -5 /workspace/blog.html' \< /dev/null && pwd -P >| /tmp/claude-5f6c-cwd
exec  wc: wc -c /workspace/blog.html
file  wc: 131072 /workspace/blog.html
exec  head: head -5 /workspace/blog.html
file  head: 131072 /workspace/blog.html
file  node: 131072 /workspace/blog.html
conn  node: AF_INET 8.8.8.8:53
dns   node → api.anthropic.com A
conn  node: AF_INET 8.8.8.8:53
dns   node → http-intake.logs.us5.datadoghq.com A
conn  claude: AF_INET 160.79.104.10:443
conn  claude: AF_INET 34.149.66.137:443
```

</details>

</details>

### Configure

Configuration is YAML and works at two levels:

- **Global** (`~/.membrane/config.yaml`): Applies to every workspace. Written from the default template on first run. Edit this to set your baseline allow list, ignore patterns, and readonly patterns.
- **Workspace** (`.membrane.yaml` in your project root): Applies to the current workspace only. Lists in the workspace config are appended to the global config, not replaced.

```yaml
# `ignore` lists patterns matched against filenames or relative paths.
# Matching files and directories are shadowed with an empty placeholder
# inside the container; the agent can see they exist but cannot read
# their contents.
ignore:
  - secrets/
  - "*.pem"

# `readonly` lists patterns mounted into the container as read-only. Use
# this for things like .git (so the agent can read history but not
# rewrite it) or credential files that should be visible but not
# writable.
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
        paths: [/api/]
  - dest: github.com   # second entry adds port 22
    ports: [22/tcp]

  # 5. URL entry: shorthand for hostname + port from scheme + path
  # prefix. All methods allowed under /v1/.
  - https://api.openai.com/v1/

  # 6. URL entry with http rules: the most specific form. Port from
  # scheme enforced at L3, method and path enforced at L7.
  - dest: https://api.example.com/v1/
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
        paths: [/api/]

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

# `args` lists raw arguments appended to the `docker run` command.
# Environment variables are expanded ($VAR, ${VAR}). Each flag and
# its argument must be separate items.
args:
  - -e
  - MY_API_KEY=abc123
  - -v
  - $HOME/.aws:/home/agent/.aws:ro
  - -e
  - AWS_PROFILE=myprofile
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
- [ ] move tracee from dedicated sidecar into handler
- [ ] per-session home dir overlay
- [ ] support trusting specific CA certs
- [ ] return error messages from proxy
- [ ] add debug flag

<details><summary>Completed</summary>

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
- [x] make ignore/readonly configurable
- [x] allow reading from host stdin (to be used in pipeline)
- [x] auto-install prerequisites on first run

</details>
