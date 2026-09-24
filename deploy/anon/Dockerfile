# anon v0.4.10.2, the Anyone daemon a HIDDEN provider box runs (HIDDEN=1,
# docker-compose.hidden.yml, README § "Running hidden").
#
# Built on the box, never pulled, and that is not a preference.
# ghcr.io/anyone-protocol/ator-protocol publishes no image for v0.4.10.2: its
# release tags stop at v0.4.9.7, and its `latest` is a 0.4.9.x build. Those
# releases publish `.onion` addresses, and the rename to `.anyone` is total in
# both directions: v0.4.10.2 writes `<56 base32>.anyone` and refuses the same
# address spelled `.onion`, and a provider refuses a `connector_url` that is
# not `.anyone`. So this image lays the official v0.4.10.2 release binary over
# the v0.4.9.7 image, which keeps that image's contract (the `anond` user,
# /var/lib/anon and its ownership, the entrypoint). The binary is statically
# linked, so nothing else has to come with it.
#
# The same file as infra/sandbox/anon/Dockerfile, which the sandbox's `hs`
# profile proves a hidden provider against, with one difference: the base is
# pinned by DIGEST here as well as by tag. A tag can be moved; a digest and
# the binary's sha256 below cannot, so what builds on a box is what was
# reviewed. Both change only by a reviewed commit to this file.
#
# amd64 only: the checksum below is the amd64 release zip's, and it is the
# figure toon-client and anytoon record for the same file. An arm64 box needs
# the arm64 zip and its own checksum, taken from the release and checked
# against a second source, not trusted on first download.
FROM ghcr.io/anyone-protocol/ator-protocol:v0.4.9.7@sha256:71eed597bec3877ffe9a4ffb601336f3f8b700d93ca59a33a2ca1630b214cd94

ARG ANON_VERSION=v0.4.10.2
# sha256 of anon-live-linux-amd64.zip. Checked BEFORE the binary is ever
# executed: an unverified download is not an upgrade.
ARG ANON_SHA256=9c6498b8d27de54d78842a1b854979a605f9c140ccc34f2b4c267bf094eaeb17

USER root
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl unzip ca-certificates; \
    # iptables is KEPT (curl and unzip are not). This daemon is the transparent
    # egress of the internal network every hidden workload is on, and a
    # TransPort is reachable only through the nat PREROUTING REDIRECT rules
    # its own container installs at boot (docker-compose.hidden.yml). Debian's
    # iptables is the nft backend; the rules live in that container's own
    # network namespace, never the host's.
    apt-get install -y --no-install-recommends iptables; \
    curl -fsSL -o /tmp/anon.zip \
      "https://github.com/anyone-protocol/ator-protocol/releases/download/${ANON_VERSION}/anon-live-linux-amd64.zip"; \
    echo "${ANON_SHA256}  /tmp/anon.zip" | sha256sum -c -; \
    unzip -o -j /tmp/anon.zip -d /tmp/anon; \
    install -m 0755 /tmp/anon/anon /usr/local/bin/anon; \
    install -m 0644 /tmp/anon/geoip  /usr/local/share/anon/geoip; \
    install -m 0644 /tmp/anon/geoip6 /usr/local/share/anon/geoip6; \
    rm -rf /tmp/anon /tmp/anon.zip; \
    apt-get purge -y curl unzip; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*; \
    # Fail the BUILD, not the first bring-up, if the wrong release was fetched.
    anon --version | grep -q "0.4.10.2"
