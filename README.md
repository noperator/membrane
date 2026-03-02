<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="img/logo-dark.png">
    <img alt="logo" src="img/logo-light.png" width="500px">
  </picture>
  <br>
  Agent in a cage.
</p>

Locks down the network and filesystem so an agent is free to explore the mounted workspace while reducing the risk of it going off the rails.

## Description

cagent runs your AI agent inside a Docker container with two hard constraints:

- **Network:** An nftables firewall allows outbound traffic only to an explicit domain allowlist. Domains are resolved at startup and refreshed continuously. Everything else is dropped.
- **Filesystem:** The workspace is mounted into the container, but sensitive files and directories can be hidden entirely (shadowed with an empty placeholder) or made read-only. This prevents the agent from reading secrets, corrupting `.git` history, or modifying its own configuration.

The agent runs as an unprivileged user. CAP_NET_ADMIN and CAP_NET_RAW are dropped after firewall setup so no process inside the container (including privileged inner containers) can modify the firewall rules or craft raw packets to bypass them.

## Getting started

### Prerequisites

- Docker
- Linux with [Sysbox](https://github.com/nestybox/sysbox#installation) if you want to run nested Docker-in-Docker containers

### Install

```bash
go install github.com/noperator/cagent/cmd/cagent@latest
```

On first run, cagent will clone the repo to `~/.cagent/src`, build the Docker image, and write a default config to `~/.cagent/config.yaml`. Subsequent runs check for updates automatically.

```bash
cd /your/workspace
cagent
```

### Configure

Configuration is YAML and works at two levels:

- **Global** (`~/.cagent/config.yaml`): Applies to every workspace. Written from the default template on first run. Edit this to set your baseline domains, ignore patterns, and readonly patterns.
- **Workspace** (`.cagent.yaml` in your project root): Applies to the current workspace only. Lists in the workspace config are appended to the global config, not replaced.

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

### Usage

```
cagent -h

Usage: cagent [options] [-- command...]

Options:
      --no-update      skip checking for updates
      --reset [civd]   remove specific cagent state and exit (any combo of: c=containers, i=image, v=volume, d=directory)
      --reset-all      remove all cagent state and exit
```

Optionally pass a specific command to be executed, using `--` to separate cagent options from the command to run inside the container.

```bash
# Drop into a shell
cagent

# Run a specific command
cagent -- claude -p "just say hello"
cagent -- bash -c "echo hello"
```

#### Modifying the image

If you want to customize the Dockerfile, firewall rules, or entrypoint, edit the files in `~/.cagent/src/` and rebuild:

```bash
docker build -t cagent ~/.cagent/src/
```

If you've made local edits and an update is available, cagent will back up `~/.cagent/src/` to a timestamped directory before pulling.

#### Reset

To wipe all cagent state and start fresh:

```bash
cagent --reset-all
```

This removes running containers, the Docker image, the `cagent-home` volume, and `~/.cagent`. Workspace `.cagent.yaml` files are not affected. You can also reset individual components:

```bash
cagent --reset ci           # containers and image only
cagent --reset civd         # same as --reset-all
```

### Troubleshooting

This project is an experimental work in progress. There are likely more opportunities to lock this down further. A few common issues:

- **Network not working for a domain that should be allowed:** The firewall resolves domains to IPs at startup. If a CDN rotates IPs, the connection may fail until the next refresh (every 60s). Check `/var/log/firewall-updater.log` inside the container for refresh status.

- **Docker-in-Docker not working:** Sysbox must be installed on the host. cagent detects it automatically; if it's not present, Docker-in-Docker is silently disabled.

## Back matter

### See also

- https://github.com/trailofbits/claude-code-devcontainer
- https://github.com/RchGrav/claudebox
- https://github.com/anthropics/claude-code/tree/main/.devcontainer
- https://www.anthropic.com/engineering/claude-code-sandboxing

### To-do

- [ ] pass via config via CLI (in addition to file)
- [ ] allow reading from host stdin (to be used in pipeline)
- [ ] monitor agent with eBPF
- [ ] support Docker-in-Docker on macOS
- [ ] whitelist IPs
- [ ] set custom DNS resolver

<details><summary>Completed</summary>

- [x] specify domains at runtime
- [x] git-aware read-only mounts
- [x] refresh firewall after init
- [x] quiet down logging a bit
- [x] make ignore/readonly configurable

</details>
