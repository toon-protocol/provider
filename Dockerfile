# The provider binary. It shells out to the `docker` CLI, so a container
# running it needs the CLI and a socket it may use:
#
#   docker run -v /var/run/docker.sock:/var/run/docker.sock \
#              -v ./provider.toml:/etc/toon-provider/provider.toml \
#              toon-provider
#
# Workloads then run on the HOST daemon, and their SSH forwards and ports are
# published on the host — so `public_ip` is the host's address.
# 1.90, not 1.85. `usize::is_multiple_of` stabilised in 1.87 and the fetcher
# uses it (src/provider/fetcher.rs), so the old pin could not build this crate
# at all -- `cargo build --release` failed with E0658 while every developer's
# toolchain and CI, which run a current stable, were green. A deploy bundle
# that builds the app from the checkout (deploy/README.md) is what turned that
# into a visible failure rather than a latent one.
FROM rust:1.90-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release --locked --bin toon-provider

FROM debian:bookworm-slim

# curl for a compose healthcheck against /health; certificates for the
# daemon's registry pulls are the daemon's business, not this image's.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Only the CLI, from the official image: the `docker.io` apt package would
# drag in a whole engine this container never runs.
COPY --from=docker:28-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=builder /app/target/release/toon-provider /usr/local/bin/toon-provider

WORKDIR /var/lib/toon-provider
ENV RUST_LOG=info

# The provider's own TOON connector is the only thing that should reach this.
EXPOSE 8080

# The operator endpoint (`POST /operator/evict`, used by `toon-provider
# evict`) is deliberately NOT exposed here: it is loopback-only by config
# validation and reached from inside this same container (e.g. `docker
# compose exec provider toon-provider evict ...`), never published as a
# compose port.

ENTRYPOINT ["toon-provider"]
CMD ["--config", "/etc/toon-provider/provider.toml"]
