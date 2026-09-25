# The Hidden Provider's DNS shim (TOON_Network#166): `toon-provider dns-shim`
# (`src/dns_shim.rs` has the full account), built as an image of its own.
#
# THE PROBLEM THIS EXISTS FOR. `anon`'s own `DNSPort` answers an AAAA query
# with NXDOMAIN even when the name has a perfectly good A record — confirmed
# against the real `anon` v0.4.10.2-live daemon, over the real Anyone
# network. musl's `getaddrinfo` (Alpine's libc) asks for A and AAAA in
# parallel and discards a good A answer the moment the AAAA one comes back
# NXDOMAIN, so an Alpine workload cannot resolve any name on a Hidden
# Provider. No `anonrc` option changes it. This shim sits in front of
# `anon`'s `DNSPort`: it forwards A queries unchanged and answers every AAAA
# query itself, unconditionally, with NOERROR and no records — decided by
# QUERY TYPE alone, before anything is forwarded anywhere, so there is no
# "first query for this name" race to lose (unlike a bare `dnsmasq
# --filter-AAAA` sidecar, which `src/dns_shim.rs`'s module doc shows losing
# exactly that race).
#
# WHY ITS OWN DOCKERFILE, RATHER THAN THE PUBLISHED `provider` IMAGE. That
# image is pinned in `docker-compose.yml` by a floating `sha-<short>`, bumped
# on the whole app's own release schedule (README § "Bumping the connector
# pin") — never by digest. Pointing this service at it would mean this one
# small, rarely-touched utility could only ever be bumped alongside a full
# provider release, and could never be pinned by DIGEST the way the deploy
# README asks (TOON_Network#166's own wording). Building a binary of its own
# here, from THIS checkout, pinned by BASE IMAGE DIGEST, lets it be bumped on
# a schedule of its own, by a reviewed commit to this one file — the same
# reasoning `anon/Dockerfile` gives for pinning what IT builds from.
#
# Built here, like `anon`: `pull-images.sh` builds any service with a
# `build:` rather than pulling it, and the layer cache makes a rebuild of an
# unchanged Dockerfile a no-op. Context is the repository root (the
# `dns-shim` compose service says so) so this stage can reach `Cargo.toml`
# and `src/` — the SAME source `toon-provider`'s own image is built from,
# just a different binary out of the same crate; there is only one copy of
# `src/dns_shim.rs`'s wire logic to keep correct, and `cargo test` covers it
# whichever image ends up running it.
FROM rust:1.85-slim-bookworm@sha256:9f841bbe9e7d8e37ceb96ed907265a3a0df7f44e3737d0b100e7907a679acb36 AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release --locked --bin toon-provider

# No docker CLI, no docker.sock, no config mount: this container speaks UDP
# and TCP DNS on the egress network and nothing else.
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
COPY --from=builder /app/target/release/toon-provider /usr/local/bin/toon-provider
ENV RUST_LOG=info
ENTRYPOINT ["toon-provider"]
CMD ["dns-shim"]
