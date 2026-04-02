FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# =============================================================================
# LAYER 1: Bootstrap packages (rarely changes)
# =============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    gnupg \
    build-essential \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# LAYER 2: Language runtimes (version-pinned, rarely change)
# =============================================================================

# Node.js
ARG NODE_VERSION=20
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Python
ARG PYTHON_VERSION=3.13
RUN add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && apt-get install -y \
    python${PYTHON_VERSION} \
    python${PYTHON_VERSION}-venv \
    python${PYTHON_VERSION}-dev \
    python3-pip \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python${PYTHON_VERSION} 1 \
    && rm -rf /var/lib/apt/lists/*

# Go
ARG GO_VERSION=1.23.2
RUN wget "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" && \
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz" && \
    rm "go${GO_VERSION}.linux-amd64.tar.gz"
ENV PATH="/usr/local/go/bin:${PATH}"

# =============================================================================
# LAYER 3: User setup (rarely changes)
# =============================================================================

ARG USERNAME=agent
RUN useradd -m -s /bin/bash ${USERNAME} && \
    echo "${USERNAME}:${USERNAME}" | chpasswd

# =============================================================================
# LAYER 4: Rust (user-level install, rarely changes)
# =============================================================================

USER ${USERNAME}
WORKDIR /home/${USERNAME}
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/home/${USERNAME}/.cargo/bin:${PATH}"
USER root

# Set up Go path for agent user
ENV GOPATH="/home/${USERNAME}/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# =============================================================================
# LAYER 5: Coding agents (changes occasionally)
# =============================================================================

RUN npm install -g @anthropic-ai/claude-code@2.1.87
RUN npm install -g @openai/codex@0.118.0
# RUN npm install -g opencode-ai@latest
# RUN npm install -g @charmland/crush

# =============================================================================
# LAYER 6: Docker + crun (for optional Sysbox, rarely changes)
# =============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

RUN CRUN_VER=1.22 && \
    ARCH=$(dpkg --print-architecture) && \
    curl -L -o /usr/bin/crun "https://github.com/containers/crun/releases/download/${CRUN_VER}/crun-${CRUN_VER}-linux-${ARCH}" && \
    chmod +x /usr/bin/crun

# Add agent to docker group
RUN usermod -aG docker ${USERNAME}

# =============================================================================
# LAYER 7: Utilities (changes often - add new tools here)
# =============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network tools
    iproute2 \
    dnsutils \
    libcap2-bin \
    ncat \
    # Git and GitHub
    git \
    gh \
    # Shell utilities
    sudo \
    zsh \
    vim \
    less \
    # Other utilities
    jq \
    ripgrep \
    tree \
    unzip \
    zip \
    rsync \
    cmake \
    gosu \
    sqlite3 \
    pipx \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin UV_VERSION=0.11.2 sh

# =============================================================================
# LAYER 8: Sudo configuration (depends on utilities layer for sudo)
# =============================================================================

RUN echo "${USERNAME} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/${USERNAME} && \
    chmod 0440 /etc/sudoers.d/${USERNAME}

# =============================================================================
# LAYER 9: Scripts (changes most often - keep at bottom)
# =============================================================================

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

# =============================================================================
# Final setup
# =============================================================================

WORKDIR /workspace
ENV SHELL=/bin/bash
ENV CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
