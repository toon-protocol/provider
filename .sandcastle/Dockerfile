# The runner is Node and this repository is Rust, so the base is the stock node:22 image
# and Rust is added below. The FULL node:22-bookworm is built on buildpack-deps:bookworm,
# which bundles build-essential (gcc/g++/make) and python3, so cargo can link with no extra
# apt packages. (If you ever switch this FROM to a `-slim` variant, you MUST add
# `build-essential python3` before the USER switch.)
# Node is also what the repository's own tests need: they run tools/*.mjs.
FROM node:22-bookworm

# Links the published GHCR package (ghcr.io/toon-protocol/provider:sandcastle-agent,
# see the pull step in .github/workflows/agent-implement.yml) to this repo.
LABEL org.opencontainers.image.source="https://github.com/toon-protocol/provider"

# Install system dependencies
RUN apt-get update && apt-get install -y \
  git \
  curl \
  jq \
  gettext-base \
  && rm -rf /var/lib/apt/lists/*

# Install GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
  | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
  && apt-get update && apt-get install -y gh \
  && rm -rf /var/lib/apt/lists/*

# Build-args for UID/GID alignment: sandcastle docker build-image
# defaults these to the host user's UID/GID so image-built files
# and bind-mounted files share an owner without runtime chown.
ARG AGENT_UID=1000
ARG AGENT_GID=1000

# Rename the base image's "node" user to "agent" and align UID/GID.
RUN groupmod -o -g $AGENT_GID node && usermod -o -u $AGENT_UID -g $AGENT_GID -d /home/agent -m -l agent node
USER ${AGENT_UID}:${AGENT_GID}

# Install Claude Code CLI
RUN curl -fsSL https://claude.ai/install.sh | bash

# Matt Pocock's skills, the same plugin used interactively. The runner starts each agent
# session with `/mattpocock-skills:implement` or `/mattpocock-skills:code-review`, so they
# must be installed here. A fresh install doesn't know the official marketplace yet, so add
# it first. This takes the plugin's latest release when the image is built; rebuild the
# image to pick up a newer one.
RUN /home/agent/.local/bin/claude plugin marketplace add anthropics/claude-plugins-official \
  && /home/agent/.local/bin/claude plugin install mattpocock-skills@claude-plugins-official

# ── Rust ────────────────────────────────────────────────────────────────────
# Without it the implementer cannot run `cargo test` or `cargo clippy` on the code it is
# writing, and CI is the first thing that ever compiles it.
#
# The toolchain tracks the gate: ci.yml's `checks` job uses `dtolnay/rust-toolchain@stable`
# with clippy and rustfmt, so this installs `stable` with the same two components.
# (The root Dockerfile pins 1.85 for the shipped binary; that is not the gate's toolchain.)
# `--profile minimal` keeps it to the toolchain plus what the gate invokes.
#
# `gettext-base` above provides `envsubst`, which tests/deploy_bundle.rs needs (ci.yml
# installs it for the same reason). There is no Foundry or Solana CLI here: nothing in this
# repository's tests spawns a chain.
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain stable --component clippy,rustfmt

# Add Claude and cargo to PATH
ENV PATH="/home/agent/.local/bin:/home/agent/.cargo/bin:$PATH"

# ENV PATH covers the engine, which execs non-login shells. claude-code spawns its own
# shells, and a LOGIN shell sources /etc/profile, which rebuilds PATH from scratch. rustup
# appends itself to ~/.profile, so cargo survives `bash -lc`; the workflow's image check
# runs a login shell to keep that true.

WORKDIR /home/agent

# In worktree sandbox mode, Sandcastle bind-mounts the git worktree at /home/agent/workspace
# and overrides the working directory to /home/agent/workspace at container start.
# Structure your Dockerfile so that /home/agent/workspace can serve as the project root.
ENTRYPOINT ["sleep", "infinity"]
