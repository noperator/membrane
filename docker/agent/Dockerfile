# syntax=docker/dockerfile:1.4
FROM ubuntu:22.04 AS base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget \
    && rm -rf /var/lib/apt/lists/*

# ---- Parallel stage: Go ----
FROM base AS go-stage
ARG GO_VERSION=1.23.2
RUN ARCH=$(dpkg --print-architecture) && \
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" && \
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-${ARCH}.tar.gz"

# ---- Parallel stage: crun ----
FROM base AS crun-stage
RUN CRUN_VER=1.22 && \
    ARCH=$(dpkg --print-architecture) && \
    curl -L -o /crun "https://github.com/containers/crun/releases/download/${CRUN_VER}/crun-${CRUN_VER}-linux-${ARCH}" && \
    chmod +x /crun

# ---- Parallel stage: Node + npm globals ----
# Node is installed here and a fresh `npm install -g` runs for the agent
# packages. This stage needs build-essential and python3 so native npm
# modules compile cleanly.
FROM base AS node-stage
ARG NODE_VERSION=22
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - && \
    apt-get install -y --no-install-recommends \
        nodejs build-essential python3 \
    && rm -rf /var/lib/apt/lists/*
RUN npm install -g \
    @anthropic-ai/claude-code@2.1.286 \
    @openai/codex@0.159.2 \
    @moonshot-ai/kimi-code@2.1.1

# ---- Parallel stage: download .debs only, do not install them ----
# Runs concurrent with go-stage, crun-stage, node-stage.
# Package list MUST MATCH the final stage's apt-get install exactly —
# drift causes silent re-download, not failure, but defeats the optimization.
FROM base AS apt-cache-stage
RUN apt-get update && \
    apt-get install -y --no-install-recommends --download-only \
        build-essential \
        python3 python3-venv python3-dev python3-pip \
        docker.io \
        iproute2 dnsutils libcap2-bin ncat \
        git gh sudo zsh vim less \
        jq ripgrep tree unzip zip rsync cmake gosu sqlite3 pipx

# ---- Final stage ----
FROM base AS final

# Pre-populate both the apt cache AND the package lists from the parallel stage.
# Using both means the hashes in lists match the .debs in archives, so apt
# recognizes them as valid and skips the fetch entirely.
COPY --from=apt-cache-stage /var/cache/apt/archives /var/cache/apt/archives
COPY --from=apt-cache-stage /var/lib/apt/lists /var/lib/apt/lists

# Package list MUST MATCH apt-cache-stage. No apt-get update — the lists
# were copied from apt-cache-stage and already match the cached archives.
RUN apt-get install -y --no-install-recommends \
        build-essential \
        python3 python3-venv python3-dev python3-pip \
        docker.io \
        iproute2 dnsutils libcap2-bin ncat \
        git gh sudo zsh vim less \
        jq ripgrep tree unzip zip rsync cmake gosu sqlite3 pipx \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb

# Copy artifacts from parallel stages.
# Node binary and modules
COPY --from=node-stage /usr/bin/node /usr/bin/node
COPY --from=node-stage /usr/lib/node_modules /usr/lib/node_modules

# Recreate CLI symlinks. COPY --from follows symlinks (copying the
# target file contents), which breaks npm's relative require() paths.
# The symlinks use relative targets matching what nodesource installs.
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/bin/npm && \
    ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/bin/npx && \
    ln -s ../lib/node_modules/@anthropic-ai/claude-code/cli.js /usr/bin/claude && \
    ln -s ../lib/node_modules/@openai/codex/bin/codex.js /usr/bin/codex

COPY --from=go-stage /usr/local/go /usr/local/go
COPY --from=crun-stage /crun /usr/bin/crun

ENV PATH="/usr/local/go/bin:${PATH}"

# User setup
ARG USERNAME=agent
RUN useradd -m -s /bin/bash ${USERNAME} && \
    echo "${USERNAME}:${USERNAME}" | chpasswd && \
    usermod -aG docker ${USERNAME} && \
    printf '%s\n%s\n' \
        "${USERNAME} ALL=(ALL) NOPASSWD: ALL" \
        'Defaults:'${USERNAME}' env_keep += "NODE_EXTRA_CA_CERTS NODE_USE_SYSTEM_CA REQUESTS_CA_BUNDLE SSL_CERT_FILE CURL_CA_BUNDLE"' \
        > /etc/sudoers.d/${USERNAME} && \
    chmod 0440 /etc/sudoers.d/${USERNAME}

ENV GOPATH="/home/${USERNAME}/go"
ENV PATH="${GOPATH}/bin:${PATH}"

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /workspace
ENV SHELL=/bin/bash
ENV CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
