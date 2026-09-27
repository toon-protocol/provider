#!/usr/bin/env bash
# Puts every container the compose file pins to an `ipv4_address` back at that
# address. Run after each full `docker compose up -d` (bootstrap.sh,
# auto-apply.sh); a no-op wherever every pinned address already holds, which
# is always, on a box with no pinned addresses (the public stack).
#
# Why it exists: when a network's own config changes, `up -d` removes the
# network, recreates it, and reconnects each container that was on it WITHOUT
# the container's `ipv4_address` (Docker Compose 5.5.1). A container whose own
# config did not change is not recreated, so it keeps running at an address
# from the pool, and every later `up -d` leaves it there. On a hidden box that
# is `anon`, the first time the hidden network became `internal`
# (TOON_Network#181): it could not bind 172.30.2.2:9050 and aborted, over and
# over, and nothing that depends on it started. Recreating the container
# reattaches it at its pinned address; nothing else does.
set -euo pipefail
cd "$(dirname "$0")"

config=$(docker compose config --format json)

# One line per pin: service, the network's real (Docker) name, the address.
pins=$(jq -r '
  .networks as $networks
  | .services | to_entries[] | .key as $service
  | (.value.networks // {}) | to_entries[]
  | select((.value // {}).ipv4_address != null)
  | [$service, ($networks[.key].name // .key), .value.ipv4_address] | @tsv
' <<<"$config")

drifted=()
while IFS=$'\t' read -r service network want; do
  [ -n "$service" ] || continue
  container=$(docker compose ps -q "$service")
  # Not running is `up -d`'s business, not this script's.
  [ -n "$container" ] || continue
  have=$(docker inspect --format '{{json .NetworkSettings.Networks}}' "$container" |
    jq -r --arg n "$network" '.[$n].IPAddress // ""')
  if [ "$have" != "$want" ]; then
    echo "==> $service is at '${have:-nothing}' on $network, not its pinned $want: recreating it"
    case " ${drifted[*]} " in *" $service "*) ;; *) drifted+=("$service") ;; esac
  fi
done <<<"$pins"

if [ "${#drifted[@]}" -gt 0 ]; then
  docker compose up -d --force-recreate --no-deps "${drifted[@]}"
fi
