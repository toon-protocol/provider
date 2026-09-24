#!/usr/bin/env bash
#
# Apply what was merged. Run by systemd on a timer; see deploy/README.md.
#
# This is the box half of GitOps (connector ADR 0068): the repository is the
# deploy surface, and this script's whole job is to notice that the tracked
# branch moved and apply it.
#
# It is PULL-based on purpose. The alternative -- a CI job holding an SSH key
# into this box -- is the write path ADR 0068 deliberately removed, and putting
# it back is a wider blast radius than the tedium it saves. Nothing outside
# this box can make this box deploy.
#
# It refuses rather than guesses:
#   * a dirty working tree means a human is mid-operation here -- stop, loudly;
#   * only a fast-forward is applied, never a merge or a reset, so a box can
#     never end up on a tree nobody reviewed;
#   * after `up -d` every service must reach `healthy`, or this exits non-zero
#     so `systemctl status` and the journal show it;
#   * a render or apply failure is retried, and reported, on every run until
#     it is fixed -- never silently sat on with the box left on the new
#     commit and the old config (TOON_Network#160; see `deploy/.applied`,
#     below the fetch, for how).
#
# ── One deliberate difference from the store and relay copies ────────────────
# IT TRACKS A NAMED BRANCH. `TRACK_BRANCH` in .env, defaulting to `main`,
# because the devnet provider runs ahead of this repository's `main` while
# a milestone is unmerged, and a box silently following a branch that does
# not exist would report success every five minutes while standing still.
#
# ── And one difference from the gateway's copy ───────────────────────────────
# THE PROVIDER APP HAS RENDERED CONFIG OF ITS OWN, and it reads it once at
# startup as the connector does. A listing change is a provider.toml change and
# a connector.toml change together, and both processes have to be bounced for
# it -- in that order, connector first (README, "Changing a listing's price"),
# so that no packet is ever priced by a connector for a tier the app has
# already stopped selling.
set -euo pipefail

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
DEPLOY_DIR="$REPO_DIR/deploy"
cd "$REPO_DIR"

TRACK_BRANCH=main
if [ -f "$DEPLOY_DIR/.env" ]; then
  # Only this one variable, and only from a well-formed line: sourcing .env
  # here would pull this provider's Nostr key and the publisher's mnemonic into
  # this script's environment for no reason at all.
  value=$(sed -n 's/^[[:space:]]*TRACK_BRANCH[[:space:]]*=[[:space:]]*//p' "$DEPLOY_DIR/.env" | tail -n 1 | tr -d '"'"'"' \t\r')
  [ -n "$value" ] && TRACK_BRANCH=$value
fi

# The [node] addresses a connector.toml advertises, one per line, sorted.
# Scoped to the [node] table (the sed range runs from `[node]` to the next
# table header), so an `addresses = [...]` under any other table can never leak
# into the comparison. KNOWN LIMIT: the sed matches a single-line
# `addresses = [...]` only; a reformatted template parses EMPTY, which the
# caller below refuses loudly instead of letting the verification pass
# vacuously.
advertised_addresses() {
  sed -n '/^\[node\]/,/^[[:space:]]*\[/s/^[[:space:]]*addresses[[:space:]]*=[[:space:]]*\[\(.*\)\].*/\1/p' "$1" \
    | grep -o '"[^"]*"' | tr -d '"' | sort -u || true
}

# Every file render.sh writes that docker-compose.yml bind-mounts into the
# connector, plus the hand-placed key files: a change to ANY of them needs a
# connector restart to become live, not just connector.toml -- a rotated
# OPERATOR_WRITE_KEY re-renders only operator-write.keys, and a revoked key
# that stays authorised is a security bug. Missing files are tolerated (first
# render) and count as a change once they appear.
fingerprint_connector_inputs() {
  { sha256sum \
      connector.toml \
      operator-bearer.token \
      operator-write.keys \
      signer.key \
      settlement.key \
      settlement-solana.key \
      2>/dev/null || true; } | sha256sum | awk '{print $1}'
}

# The provider app's own input set. One file, and it is the whole of what this
# provider sells: the listings, the prices, the capacities, the identity it
# signs with, and the connector key it tells tenants to seal to.
fingerprint_provider_inputs() {
  { sha256sum provider.toml 2>/dev/null || true; } | sha256sum | awk '{print $1}'
}

# One apply at a time, and never one racing a human. The path is overridable
# only for tests (TOON_AUTOAPPLY_LOCK) -- a box always takes the real one.
LOCK_FILE=${TOON_AUTOAPPLY_LOCK:-/var/lock/toon-auto-apply.lock}
exec 9>"$LOCK_FILE"
flock -n 9 || { echo "another apply is already running; leaving it alone"; exit 0; }

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "REFUSING: the working tree at $REPO_DIR is dirty."
  echo "Someone is editing on the box. Commit, stash or discard it, then this resumes on its own."
  exit 1
fi

if ! git fetch -q origin "$TRACK_BRANCH"; then
  echo "FAILED: origin has no branch '$TRACK_BRANCH'. Set TRACK_BRANCH in deploy/.env."
  exit 1
fi
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse FETCH_HEAD)

# The commit the LAST run applied AND VERIFIED, held separately from HEAD
# (TOON_Network#160). Without it, "LOCAL = REMOTE" alone reads as "nothing to
# do" even when the PREVIOUS run fast-forwarded here and then failed partway
# through -- render.sh, pull-images.sh, `up -d`, or a health or activation
# check below -- which leaves the box sitting on the new commit with the OLD
# rendered config and the OLD containers, reporting success on every run
# after. Comparing HEAD to `.applied` instead of to what was just fetched
# means a fetch that brings back nothing new is still retried as work when
# the two disagree.
#
# Missing entirely -- an existing box's first run under this check, or one
# whose `deploy/.applied` was lost -- is read the SAFER of the two ways: as
# needing an apply, not as "must already be applied". Re-running the full
# apply against a box already on the right commit with healthy containers is
# a harmless no-op (the fingerprints and the `GET /ilp` comparison below find
# nothing to change), where guessing the other way would paper over a first
# apply that had in fact failed before this file ever existed. bootstrap.sh
# deliberately does not write it either: the box's first-ever apply IS this
# script's first run, and it should prove itself exactly like every later
# one does.
APPLIED_FILE="$DEPLOY_DIR/.applied"
APPLIED=$(cat "$APPLIED_FILE" 2>/dev/null || true)

if [ "$LOCAL" = "$REMOTE" ] && [ "$LOCAL" = "$APPLIED" ]; then
  exit 0   # nothing merged since last time, and it is already applied
fi

if [ "$LOCAL" != "$REMOTE" ]; then
  echo "applying ${LOCAL:0:7} -> ${REMOTE:0:7} (origin/$TRACK_BRANCH)"
  git merge --ff-only FETCH_HEAD
else
  echo "retrying ${LOCAL:0:7}: the last apply did not finish (deploy/.applied is '${APPLIED:-<none>}')"
fi

cd "$DEPLOY_DIR"
# Both configs are RENDERED, so a pulled template change is not live until
# render.sh has run -- and the rendered files are BIND-MOUNTED, so `up -d`
# recreates a container on a changed image or definition, never on changed
# bytes behind a bind mount. Fingerprint both input sets around render.sh; a
# missing pre-render file counts as changed, and WHY it changed does not
# matter.
#
# The fingerprints alone are NOT the whole restart decision for the connector.
# They compare this run's disk to this run's disk, which says nothing about
# what the RUNNING connector loaded. The decision below also asks it what it
# serves and compares that to the render, so a box already sitting on a stale
# config self-heals on the next apply even when no file byte moved.
CONNECTOR_SUM_BEFORE=$(fingerprint_connector_inputs)
PROVIDER_SUM_BEFORE=$(fingerprint_provider_inputs)
if ! ./render.sh; then
  echo "FAILED: render.sh could not render the config for ${REMOTE:0:7} (its message is" >&2
  echo "above). If it names a missing .env variable, add it -- deploy/.env.example lists" >&2
  echo "every required one, with the devnet preset for settlement. deploy/.applied is" >&2
  echo "left naming the last commit that DID apply, so this is retried, and reported the" >&2
  echo "same way, on every run, until it is fixed." >&2
  exit 1
fi
CONNECTOR_SUM_AFTER=$(fingerprint_connector_inputs)
PROVIDER_SUM_AFTER=$(fingerprint_provider_inputs)

# No `-f`: compose reads COMPOSE_FILE from .env, which is how a hidden box
# (HIDDEN=1) adds docker-compose.hidden.yml, and with no COMPOSE_FILE it is
# docker-compose.yml alone, exactly as before. An explicit `-f` here would
# silently apply the public stack to a hidden box.
COMPOSE=()

# Captured before `up -d` so a recreation is distinguishable: a recreated
# container already booted on the just-rendered files and must not be bounced a
# second time for the same change.
CONNECTOR_BEFORE_UP=$(docker compose "${COMPOSE[@]}" ps -q provider-connector || true)
PROVIDER_BEFORE_UP=$(docker compose "${COMPOSE[@]}" ps -q provider || true)

# Every service is a published image now (TOON_Network#151): `provider` and
# `directory-publisher` pull the immutable pin `docker-compose.yml` names, the
# same as the connector already did. No `--ignore-*` flags: a pull that fails
# is a real problem (a bad pin, an unpublished tag, GHCR unreachable) and this
# fails loudly on it rather than bring up a stale container. The one
# exception is pull-images.sh's: while a pin is still the sha-0000000
# placeholder, that image is built from the checkout just fast-forwarded.
if ! ./pull-images.sh; then
  echo "FAILED: pull-images.sh could not get the images for ${REMOTE:0:7} (its message is" >&2
  echo "above). deploy/.applied is left naming the last commit that DID apply, so this is" >&2
  echo "retried, and reported the same way, on every run, until it is fixed." >&2
  exit 1
fi
if ! docker compose "${COMPOSE[@]}" up -d; then
  echo "FAILED: 'docker compose up -d' failed for ${REMOTE:0:7} (its message is above)." >&2
  exit 1
fi

# A service must reach `healthy`. Docker resets Health.Status to `starting` on
# restart, so calling this right after a restart cannot read a stale `healthy`.
wait_healthy() {
  local service=$1 container status
  container=$(docker compose "${COMPOSE[@]}" ps -q "$service")
  for _ in $(seq 1 40); do
    status=$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}')
    [ "$status" = healthy ] && return 0
    sleep 3
  done
  echo "FAILED: $service is '${status:-unknown}' after applying ${REMOTE:0:7}."
  docker compose "${COMPOSE[@]}" logs --tail 40 "$service" || true
  return 1
}

wait_healthy provider || exit 1
wait_healthy provider-connector || exit 1
# The publisher is the one service that can be unhealthy without anything a
# tenant is doing failing: a provider whose directory events are not being paid
# for simply stops appearing in the directory. It still fails the apply --
# silently vanishing from the Provider Directory is exactly the kind of outage
# nobody notices until a console shows an empty list.
wait_healthy directory-publisher || exit 1

# Ask the RUNNING connector what it advertises (GET /ilp, unauthenticated, on
# the loopback-published port from docker-compose.yml). Only the ilpAddresses
# array: the body also lists routes[].prefix, and comparing anything wider
# would fail every healthy apply.
#
# A curl failure is a FAILURE of this function (distinct exit), never an empty
# address list: an unreachable /ilp must be reported as unreachable, not as a
# config mismatch. The curl retries first so one connection blip does not leave
# the box unverified until the next merge.
ILP_PORT=$({ sed -n "s/.*'127\.0\.0\.1:\([0-9]*\):[0-9]*'.*/\1/p" docker-compose.yml | head -n 1; } || true)
ILP_PORT=${ILP_PORT:-4000}
served_ilp_addresses() {
  local body
  body=$(curl -fsS --retry 3 --retry-delay 2 --retry-all-errors --max-time 10 \
    "http://127.0.0.1:${ILP_PORT}/ilp") || return 1
  printf '%s' "$body" | tr -d ' \t\r\n' \
    | grep -o '"ilpAddresses":\[[^]]*\]' | head -n 1 \
    | sed 's/^"ilpAddresses"://' \
    | grep -o '"[^"]*"' | tr -d '"' | sort -u || true
}

WANT=$(advertised_addresses connector.toml)
if [ -z "$WANT" ]; then
  echo "FAILED: parsed no addresses out of the rendered connector.toml's [node] block."
  echo "The activation check below would pass vacuously; fix the template or the parser."
  exit 1
fi

if ! GOT=$(served_ilp_addresses); then
  echo "FAILED: GET /ilp on 127.0.0.1:${ILP_PORT} is unreachable while the connector reports healthy."
  docker compose "${COMPOSE[@]}" logs --tail 40 provider-connector || true
  exit 1
fi

CONNECTOR_AFTER_UP=$(docker compose "${COMPOSE[@]}" ps -q provider-connector)
PROVIDER_AFTER_UP=$(docker compose "${COMPOSE[@]}" ps -q provider)

CONNECTOR_NEEDS_RESTART=0
if [ "$CONNECTOR_SUM_AFTER" != "$CONNECTOR_SUM_BEFORE" ] && [ "$CONNECTOR_AFTER_UP" = "$CONNECTOR_BEFORE_UP" ]; then
  echo "the connector's rendered inputs changed; restarting it to activate them"
  CONNECTOR_NEEDS_RESTART=1
fi
if [ "$GOT" != "$WANT" ]; then
  echo "the running connector serves addresses that differ from the rendered config; restarting it"
  CONNECTOR_NEEDS_RESTART=1
fi

PROVIDER_NEEDS_RESTART=0
if [ "$PROVIDER_SUM_AFTER" != "$PROVIDER_SUM_BEFORE" ] && [ "$PROVIDER_AFTER_UP" = "$PROVIDER_BEFORE_UP" ]; then
  echo "provider.toml changed; restarting the app to activate it"
  PROVIDER_NEEDS_RESTART=1
fi

# CONNECTOR FIRST, THEN THE APP. A listing change lands in both files, and for
# the moment between the two restarts one of them is stale. Stale-connector is
# the harmless order: it prices a route the app still serves. The other way
# round, the app would have stopped selling a tier the connector was still
# charging for -- a packet taken and then refused, and TOON_Network ADR 0003
# says a refusal on a paid route is still billed.
if [ "$CONNECTOR_NEEDS_RESTART" = 1 ]; then
  docker compose "${COMPOSE[@]}" restart provider-connector
  wait_healthy provider-connector || exit 1
  if ! GOT=$(served_ilp_addresses); then
    echo "FAILED: GET /ilp on 127.0.0.1:${ILP_PORT} is unreachable after restarting for activation."
    docker compose "${COMPOSE[@]}" logs --tail 40 provider-connector || true
    exit 1
  fi
fi

if [ "$PROVIDER_NEEDS_RESTART" = 1 ]; then
  # A restart does NOT end a lease: the lease table is on a named volume and is
  # reloaded, and a running workload is a sibling container on the host daemon
  # that this process never stopped. It DOES republish the Profile and the
  # Listings, which is what a listing change is for.
  docker compose "${COMPOSE[@]}" restart provider
  wait_healthy provider || exit 1
fi

# Both directions, so a stale extra name fails too.
if [ "$GOT" != "$WANT" ]; then
  echo "FAILED: the running connector does not serve the rendered config, even after restarting."
  echo "rendered [node].addresses:"
  printf '%s\n' "$WANT" | sed 's/^/  /'
  echo "addresses served by GET /ilp:"
  printf '%s\n' "$GOT" | sed 's/^/  /'
  docker compose "${COMPOSE[@]}" logs --tail 40 provider-connector || true
  exit 1
fi

# nginx holds the rendered server names and is NOT recreated by a bind-mount
# change either. It is never restarted -- restarting the TLS front is what the
# other bundles go out of their way to avoid -- so tell it to reload instead,
# which re-reads conf.d and the certificate without dropping a connection.
# A hidden box has no nginx and render.sh writes it no config, so there is
# nothing to reload.
if [ -f nginx/conf.d/node.conf ] && ! cmp -s nginx/conf.d/node.conf nginx/conf.d/.node.conf.applied 2>/dev/null; then
  docker compose "${COMPOSE[@]}" exec -T nginx nginx -s reload \
    && cp nginx/conf.d/node.conf nginx/conf.d/.node.conf.applied \
    || echo "::warning:: nginx would not reload; check its logs."
fi

# Written only now, after render, the pulls, `up -d`, all three health waits
# and the activation check have all succeeded -- the one thing this file is
# allowed to claim. Gitignored (deploy/.gitignore).
printf '%s\n' "$REMOTE" > "$APPLIED_FILE"

echo "applied ${REMOTE:0:7}; provider, connector and publisher healthy, rendered config verified live."
