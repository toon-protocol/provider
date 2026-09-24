#!/usr/bin/env bash
# Get the images docker-compose.yml pins onto this box.
#
#   ./pull-images.sh              every service
#   ./pull-images.sh provider     only the ones named
#
# A pinned image is PULLED, and a pull that fails is a failure: a bad pin, an
# unpublished tag or an unreachable registry must stop an apply loudly rather
# than leave a stale container running (TOON_Network#151).
#
# ── The one exception: the placeholder pin ─────────────────────────────────
# Until publish-provider-image.yml has published its first `sha-<short>`, the
# `provider` and `directory-publisher` lines in docker-compose.yml read
# `sha-0000000`, which names nothing on GHCR. For exactly that tag, and only
# for the two images this repository builds, the image is BUILT from this
# checkout and tagged with the pinned name, so compose finds it locally and
# never asks the registry. A build of the provider compiles the Rust app, which
# needs at least 4 GB of RAM (README § "Sizing the box"); once the pin is a
# real published tag, none of this runs and the box only pulls.
#
# ── And one service that is always built: the hidden box's anon daemon ─────
# docker-compose.hidden.yml's `anon` has a `build:` of its own, because no
# registry publishes the anon release a hidden provider needs (anon/Dockerfile
# says why, and pins what it builds from by digest and sha256). A service
# with a `build:` is built, never pulled: a pull would ask a registry for a
# name that only exists on this box. The layer cache makes a rebuild of an
# unchanged Dockerfile a no-op.
set -euo pipefail
cd "$(dirname "$0")"

PLACEHOLDER=sha-0000000

# The Dockerfile each self-built service comes from, relative to the repo
# root, which is the build context of both.
dockerfile_for() {
  case "$1" in
    provider) echo Dockerfile ;;
    directory-publisher) echo tools/publisher/Dockerfile ;;
    *) return 1 ;;
  esac
}

if [ "$#" -gt 0 ]; then
  services=("$@")
else
  mapfile -t services < <(docker compose config --services)
fi

pull=()
for service in "${services[@]}"; do
  # The service's own image only: `config --images <service>` also lists the
  # images of whatever the service depends_on (provider -> directory-publisher).
  image=$(docker compose config --format json | jq -r --arg s "$service" '.services[$s].image')
  if docker compose config --format json | jq -e --arg s "$service" '.services[$s].build' >/dev/null; then
    docker compose build --quiet "$service" >&2
  elif [ "${image##*:}" = "$PLACEHOLDER" ] && dockerfile=$(dockerfile_for "$service"); then
    echo "::warning:: $image is the placeholder pin (nothing published yet); building $service from this checkout instead." >&2
    docker build --quiet -t "$image" -f "../$dockerfile" .. >&2
  else
    pull+=("$service")
  fi
done

if [ "${#pull[@]}" -gt 0 ]; then
  docker compose pull --quiet "${pull[@]}" >&2
fi
