<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="img/logo-dark-3.png">
    <img alt="logo" src="img/logo-light-3.png" width="500px">
  </picture>
  <br>
  Selectively permeable boundary for AI agents.
</p>

## Description

Membrane is a lightweight, agent-agnostic, cross-platform sandbox that gives you real-time visibility into everything that your agent does.

### Features

| | Membrane | Others |
|---|---|---|
| **Network** | Approved hostnames are whitelisted, DNS-resolved at startup, and refreshed continuously | Generally unsupported, or requires manual iptables rules that are easy to misconfigure |
| **Filesystem** | Sensitive files shadowed with empty placeholders so the agent sees they exist but cannot read them; other paths mounted read-only | No granular controls on top of bind mounts |
| **Observability** | eBPF traces *everything* that crosses the boundary: processes, DNS queries, file opens, network connections | No runtime visibility into what the agent is actually doing |
| **Nested containers** | Docker-in-Docker via Sysbox, no privileged mode or hypervisor required | Requires `--privileged` (unsafe) or full microVM |
| **Agent compatibility** | Wraps any process, agent-agnostic by design | Tightly coupled to a specific agent (Claude Code, Codex, etc.) |
| **OS support** | Linux and macOS via Docker; strong enforcement on both platforms | Enforcement mechanisms are often platform-specific: nftables and Landlock are Linux-only, Seatbelt is macOS-only |
| **Overhead** | Container-based, near-zero startup overhead on top of Docker | MicroVM-based tools require a separate kernel and hypervisor |

## Getting started

### Install

```bash
go install github.com/noperator/membrane/cmd/membrane@latest
ln -s $(go env GOPATH)/bin/membrane $(go env GOPATH)/bin/mb  # optional short alias
```

On first run, membrane will clone the repo to `~/.membrane/src/`, build the Docker image, and write a default config to `~/.membrane/config.yaml`. Subsequent runs check for updates automatically.

```bash
cd /your/workspace
membrane
```

### Usage

```
membrane -h

Usage: membrane [options] [-- command...]

Options:
      --no-trace           disable Tracee eBPF sidecar
      --no-update          skip checking for updates
      --reset[=cid]        remove membrane state and exit (c=containers, i=image, d=directory)
      --trace-log string   path for trace log file (default: ~/.membrane/trace/<id>.jsonl.gz)
```

Optionally pass a specific command to be executed, using `--` to separate membrane options from the command to run inside the container.

```bash
# Drop into a shell
membrane

# Run a specific command
membrane -- claude -p "just say hello"
membrane -- bash -c "echo hello"
```

<details><summary>Advanced usage</summary>

#### Modify the image

If you want to customize the Dockerfile, firewall rules, or entrypoint, edit the files in `~/.membrane/src/` and rebuild:

```bash
docker build -t membrane ~/.membrane/src/
```

If you've made local edits and an update is available, membrane will back up `~/.membrane/src/` to a timestamped directory before pulling.

#### Reset

`membrane --reset` will remove running containers, the Docker image, and `~/.membrane/`. Workspace `.membrane.yaml` files are not affected. You can also reset individual components:

```bash
membrane --reset=cid   # all
membrane --reset=ci    # containers and image only
```

### Trace execution

By default, membrane records a eBPF trace of everything the agent does. In this example, I just tell Claude to go download the homepage of my blog.

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

- **Global** (`~/.membrane/config.yaml`): Applies to every workspace. Written from the default template on first run. Edit this to set your baseline domains, ignore patterns, and readonly patterns.
- **Workspace** (`.membrane.yaml` in your project root): Applies to the current workspace only. Lists in the workspace config are appended to the global config, not replaced.

```yaml
# Patterns matched against filenames or relative paths. Matching files and
# directories are shadowed with an empty placeholder inside the container. The
# agent can see that they exist but cannot read their contents.
ignore:
  - secrets/
  - "*.pem"

# Patterns mounted into the container as read-only. Use this for things like
# `.git` (so the agent can read history but can't rewrite it) or `.env` files
# (visible but not writable).
readonly:
  - config/

# Hostnames the agent is allowed to reach. The firewall resolves these to IPs at
# startup and refreshes every 60s. Anything not on the list is dropped.
domains:
  - internal.mycompany.com

# Raw arguments appended to `docker run`. Useful for passing environment
# variables, additional mounts, or port mappings. Supports `~/` and `$HOME/`
# expansion.
extra_args:
  - -e
  - MY_API_KEY=abc123
```

See [`config-default.yaml`](config-default.yaml) for the full default config including the built-in domain allowlist.


### Troubleshooting

This project is an experimental work in progress. There are likely more opportunities to lock this down further. A few common issues:

- **Network not working:** The firewall resolves domains to IPs at startup. If a CDN rotates IPs, the connection may fail until the next refresh (every 60s). Check `/var/log/firewall-updater.log` inside the container for refresh status.

- **Docker-in-Docker not working:** Sysbox must be installed on the host. membrane detects it automatically; if it's not present, Docker-in-Docker is silently disabled.

## Back matter

### See also

- https://github.com/trailofbits/claude-code-devcontainer
- https://github.com/RchGrav/claudebox
- https://github.com/anthropics/claude-code/tree/main/.devcontainer
- https://www.anthropic.com/engineering/claude-code-sandboxing

### To-do

- [ ] pass via config via CLI (in addition to file)
- [ ] allow reading from host stdin (to be used in pipeline)
- [ ] support Docker-in-Docker on macOS
- [ ] whitelist IPs
- [ ] set custom DNS resolver
- [ ] support Docker checkpoint

<details><summary>Completed</summary>

- [x] mount agent home dir as ~/.membrane/home on host
- [x] monitor agent with eBPF
- [x] specify domains at runtime
- [x] git-aware read-only mounts
- [x] refresh firewall after init
- [x] quiet down logging a bit
- [x] make ignore/readonly configurable

</details>
