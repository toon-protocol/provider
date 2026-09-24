# The provider binary. It shells out to the `docker` CLI, so a container
# running it needs the CLI and a socket it may use:
#
#   docker run -v /var/run/docker.sock:/var/run/docker.sock \
#              -v ./provider.toml:/etc/toon-provider/provider.toml \
#              toon-provider
#
# Workloads then run on the HOST daemon, and their SSH forwards and ports are
# published on the host — so `public_ip` is the host's address.
FROM rust:1.85-slim-bookworm AS builder

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
# So `docker exec … toon-provider <command>` (`status`, `topup`, `evict`) finds
# the config the compose service mounts without `--config`.
ENV TOON_PROVIDER_CONFIG=/etc/toon-provider/provider.toml

# The provider's own TOON connector is the only thing that should reach this.
EXPOSE 8080

# The operator endpoint (`POST /operator/evict`, used by `toon-provider
# evict`) is deliberately NOT exposed here: it is loopback-only by config
# validation and reached from inside this same container (e.g. `docker
# compose exec provider toon-provider evict ...`), never published as a
# compose port.

ENTRYPOINT ["toon-provider"]
CMD ["--config", "/etc/toon-provider/provider.toml"]
