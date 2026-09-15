# The provider binary. It shells out to the `docker` CLI, so a container
# running it needs the CLI and a socket it may use:
#
#   docker run -v /var/run/docker.sock:/var/run/docker.sock \
#              -v ./provider.toml:/etc/toon-provider/provider.toml \
#              toon-provider
FROM rust:1.85-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release --locked --bin toon-provider

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/toon-provider /usr/local/bin/toon-provider

WORKDIR /var/lib/toon-provider
ENV RUST_LOG=info

# The provider's own TOON connector is the only thing that should reach this.
EXPOSE 8080

ENTRYPOINT ["toon-provider"]
CMD ["--config", "/etc/toon-provider/provider.toml"]
