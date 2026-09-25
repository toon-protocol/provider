#!/usr/bin/env bash
# Bring the provider box up from a fresh Ubuntu host. Idempotent — re-running
# it reconciles the box rather than rebuilding it.
#
#   ./bootstrap.sh
#
# Expects .env, the listings file it names and the three connector key files
# to already be in this directory (./keys.sh init makes the keys), and the
# keys ./keys.sh addresses lists to be funded; see README.md § "Standing one
# up". Everything it installs is
# listed here, and it makes no changes outside this directory, ufw, docker,
# journald and the systemd units it owns.
#
# With HIDDEN=1 in .env it stands up a Hidden Provider instead (README §
# "Running hidden"): it opens no public port but SSH, starts the anon daemon
# and copies the box's `.anyone` address into .env before anything else, and
# installs no certificate, since there is no public name to certify.
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] || { echo "Missing .env — run ./keys.sh init, then fill in the rest of it." >&2; exit 1; }
for f in signer.key settlement.key settlement-solana.key; do
  [ -f "$f" ] || { echo "Missing $f — run ./keys.sh init (README.md § Standing one up)." >&2; exit 1; }
done

set -a; . ./.env; set +a
: "${ILP_ADDRESS:?set ILP_ADDRESS in .env}"
HIDDEN=${HIDDEN:-0}
if [ "$HIDDEN" != 1 ]; then
  : "${DOMAIN:?set DOMAIN in .env}"
  : "${PUBLIC_IP:?set PUBLIC_IP in .env}"
fi
# Checked here as well as in render.sh so a missing one stops this before it
# has touched the firewall, not five steps in.
[ -f "${LISTINGS_FILE:-listings.toml}" ] || {
  echo "Missing ${LISTINGS_FILE:-listings.toml} — cp listings.example.toml listings.toml and edit it." >&2
  exit 1
}

echo "==> Keys and funding"
# Before anything is installed or started: an unfunded Solana settlement key
# is a connector that restart-loops at step 5 with the reason buried in its
# log, and an unfunded publisher is a provider nobody can find. keys.sh asks
# the Solana RPC for both balances (a free read) and, when one is short,
# refuses here with every address to fund and what to fund it with -- the
# list ./keys.sh addresses prints.
#
# On a box that has booted before (CONNECTOR_SEAL_KEY is recorded, step 5) a
# shortfall is a warning, not a refusal: a re-run reconciles a working box,
# and the publisher's deposit is already in its channel, not in its wallet.
# An RPC that does not answer is a warning either way. A hidden box asks only
# its own Solana node, never a public one, and on the default proxied preset
# it asks nothing at all, because anon is not running yet (keys.py says why).
command -v python3 >/dev/null 2>&1 || { apt-get update -y && apt-get install -y python3-minimal; }
funded=0
if [ -n "${CONNECTOR_SEAL_KEY:-}" ]; then
  ./keys.sh check-funded --warn-only || funded=$?
else
  ./keys.sh check-funded || funded=$?
fi
if [ "$funded" = 1 ]; then exit 1; fi

echo "==> [1/9] Firewall"
# SSH, HTTP (ACME), HTTPS — and the workload ranges, which is what makes this
# box different from every other one in the fleet. A tenant reaches its
# workload at PUBLIC_IP:<host port>: the SSH forward for its lease, and the
# sixteen published ports of its block. Those are raw TCP on this address and
# they are supposed to be reachable.
#
# The ranges here MUST agree with provider.toml's ssh_port_start,
# workload_port_start and workload id range. tests/deploy_bundle.rs checks that
# they do, because a mismatch is a workload nobody can reach and a lease that
# was still paid for.
#
# Note that docker publishes ports by writing iptables rules that BYPASS ufw,
# so opening them here does not make them reachable — they already were. It
# makes `ufw status` tell the truth about this box, which matters when the next
# person reads it.
#
# A HIDDEN box opens SSH and nothing else: no ACME, no TLS edge, no workload
# range. Everything a tenant reaches arrives over a circuit the anon daemon
# dialled OUT for, and the workload ports docker still publishes on this host
# are closed in DOCKER-USER by hidden-firewall.sh (step 4), because ufw cannot
# close what docker opens.
apt-get update -y
apt-get install -y ufw curl gettext-base openssl jq
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp  comment 'SSH'
if [ "$HIDDEN" = 1 ]; then
  # The anon daemon, and only it, reaches a lease's ports: it dials them at
  # the hidden network's gateway, through docker-proxy, so they arrive on
  # INPUT, where this is the one allowance. 172.30.2.2 is its pinned address
  # (docker-compose.hidden.yml); the ranges are the public box's, below.
  ufw allow proto tcp from 172.30.2.2 to any port 40000:40099 comment 'anon -> lease SSH forwards'
  ufw allow proto tcp from 172.30.2.2 to any port 41000:42599 comment 'anon -> lease published ports'
else
  ufw allow 80/tcp  comment 'HTTP (ACME)'
  ufw allow 443/tcp comment 'HTTPS'
  ufw allow 40000:40099/tcp comment 'workload SSH forwards'
  ufw allow 41000:42599/tcp comment 'workload published ports'
fi
ufw --force enable

echo "==> [2/9] Docker"
command -v docker >/dev/null 2>&1 || curl -fsSL https://get.docker.com | sh

echo "==> [3/9] Cap the journal"
# A provider's logs grow with its tenants'. Cap them before a workload's chatty
# container costs this box its disk.
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=200M\n' > /etc/systemd/journald.conf.d/00-cap.conf
systemctl restart systemd-journald || true

echo "==> [4/9] Pre-pull the workload sidecars"
# The `ci` tier grants `docker`, and each such lease gets a privileged daemon
# of its own beside the workload. An operator SHOULD pre-pull it: the first
# `docker` lease otherwise pays for the pull inside its own spawn, which is a
# tenant waiting for this box's bandwidth on a clock it paid for.
docker pull docker:28-dind@sha256:2a232a42256f70d78e3cc5d2b5d6b3276710a0de0596c145f627ecfae90282ac || \
  echo "::warning:: could not pre-pull the dind sidecar; the first ci lease will pull it itself."

if [ "$HIDDEN" = 1 ]; then
  # Every hidden lease runs two sidecars of this one image, pinned by digest in
  # the app (toon_provider::docker::HIDDEN_SIDECAR_IMAGE): the namespace owner
  # that points the workload's only route at anon, and the ingress forwarder
  # that holds its ports. The HOST daemon pulls it, not the provider, so an
  # unpulled one is a pull from this box's real address at the moment a lease
  # starts; pulled now, it is one pull at setup that says nothing about any
  # lease. tests/deploy_bundle.rs keeps this line equal to the app's pin.
  docker pull alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc || \
    echo "::warning:: could not pre-pull the hidden-lease sidecar; the first hidden lease will pull it itself."

  # DOCKER-USER, which ufw cannot reach: no lease port from outside the box,
  # and, if br_netfilter is loaded, the egress bridge let through.
  # Installed as a unit so it comes back after a reboot or a docker restart,
  # both of which leave the chain empty.
  if [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo 0)" = 1 ]; then
    echo "    br_netfilter is loaded: hidden-firewall.sh will accept bridged traffic on the egress bridge"
  fi
  install -m 644 toon-hidden-firewall.service /etc/systemd/system/toon-hidden-firewall.service
  systemctl daemon-reload
  systemctl enable toon-hidden-firewall.service
  systemctl restart toon-hidden-firewall.service
fi

echo "==> [5/9] The connector, and the sealing key it alone knows"
# ── First, on a hidden box: the address the connector is reached at ──────────
# The same handshake one step earlier. The connector publishes its own
# endpoint (`[node] http_endpoint`), and on a hidden box that is the `.anyone`
# address this box's anon daemon generates, which does not exist until the
# daemon has run. So: build and start the daemon alone, read the address, and
# write it into .env as HIDDEN_ADDRESS, where render.sh and every later apply
# read it. The daemon generates its key within seconds; publishing a
# descriptor for it waits on bootstrapping, which the provider waits for (its
# healthcheck), not this step.
if [ "$HIDDEN" = 1 ]; then
  ./pull-images.sh anon
  docker compose up -d --no-deps anon
  echo "    waiting for the anon daemon to generate this box's address"
  for _ in $(seq 1 40); do
    ADDRESS=$(docker compose exec -T anon cat /var/lib/anon/hidden_service/hostname 2>/dev/null | tr -d '[:space:]' || true)
    [ -n "${ADDRESS:-}" ] && break
    sleep 3
  done
  if ! printf '%s' "${ADDRESS:-}" | grep -Eqx '[a-z2-7]{56}\.anyone'; then
    echo "FAILED: read '${ADDRESS:-}' from the anon daemon, not an .anyone address." >&2
    echo "If it is empty the daemon did not start; its log says why (AgreeToTerms and the" >&2
    echo "Nickname are the usual two):" >&2
    docker compose logs --tail 40 anon >&2 || true
    exit 1
  fi
  if [ -z "${HIDDEN_ADDRESS:-}" ]; then
    printf '\n# Written by bootstrap.sh from the anon daemon. A COPY of this box%s .anyone\n# address, which is where every tenant reaches the connector.\nHIDDEN_ADDRESS=%s\n' "'s" "$ADDRESS" >> .env
    echo "    recorded HIDDEN_ADDRESS=${ADDRESS} in .env"
    set -a; . ./.env; set +a
  elif [ "$HIDDEN_ADDRESS" != "$ADDRESS" ]; then
    # The key behind the address is on the anon_data volume. A different
    # address means that volume was lost or replaced, and every Profile a
    # tenant has read names a connector that no longer answers. Say so rather
    # than quietly republishing.
    echo "FAILED: .env says HIDDEN_ADDRESS=${HIDDEN_ADDRESS}, but the anon daemon now" >&2
    echo "publishes ${ADDRESS}. The anon_data volume holding this box's address key was" >&2
    echo "lost or replaced. Restore it from a backup to keep the old address, or delete the" >&2
    echo "HIDDEN_ADDRESS line from .env and re-run to move to the new one." >&2
    exit 1
  else
    echo "    HIDDEN_ADDRESS is already in .env and the daemon agrees — kept"
  fi
fi

# A chicken and egg, resolved once and then recorded. provider.toml must carry
# the connector's sealing key VERBATIM (ADR 0011) — a tenant compares the two
# byte for byte and refuses to spawn if they differ — and the connector does
# not have an identity until it has read its own signer key and started
# serving. So: bring up the connector alone, ask it, and write the answer into
# .env, where render.sh and every later apply read it.
#
# The connector can start without provider.toml or the app: it terminates
# routes whose handler is not up yet, which is a 502 to anyone who pays one,
# not a refusal to boot.
if [ -z "${CONNECTOR_SEAL_KEY:-}" ]; then
  # Everything the connector needs and nothing that needs the connector. One
  # renderer, so the key files get their ownership fixed here too -- a
  # hand-rolled copy of this in an earlier draft did not, and the connector
  # restart-looped on "failed to read signer key_file: Permission denied"
  # while this step sat waiting for an answer it could never get.
  #
  # The connector's [[routes]] are generated by `toon-provider routes`, so
  # this is also where the provider image first reaches the box (pulled, or
  # built while its pin is the placeholder -- pull-images.sh): render.sh
  # runs the binary out of it, against a throwaway provider.toml, before the
  # app itself has anything to start with.
  ./render.sh --connector-only
  # --no-deps, and it is load-bearing. The connector `depends_on` the app, so
  # without it compose starts the app too -- and the app's bind mount names a
  # provider.toml that this step has not rendered yet, which docker answers by
  # creating an empty DIRECTORY at that path. The app then dies on "read
  # provider config at /etc/toon-provider/provider.toml: Is a directory", the
  # dependency gate fails, and the connector never starts at all. Only the
  # connector is wanted here; the app comes up in step 7 with its config.
  docker compose up -d --no-deps provider-connector

  echo "    waiting for the connector to answer GET /ilp/identity"
  for _ in $(seq 1 40); do
    SEAL=$(curl -fsS --max-time 5 http://127.0.0.1:4000/ilp/identity 2>/dev/null | jq -r '.publicKey // empty' || true)
    [ -n "${SEAL:-}" ] && break
    sleep 3
  done
  if [ -z "${SEAL:-}" ]; then
    echo "FAILED: the connector never answered GET /ilp/identity." >&2
    echo "Almost always one of: the Solana settlement key holds no SOL (it submits a" >&2
    echo "transaction at boot), a key file is not readable by uid 10001, or a settlement" >&2
    echo "address is wrong. On a hidden box, also: the anon daemon has no circuit yet (a" >&2
    echo "proxied settlement RPC fails closed until it has), or a HIDDEN_SETTLEMENT_*_RPC_URL" >&2
    echo "node is not reachable from the container, or not synced. The log says which:" >&2
    docker compose logs --tail 40 provider-connector >&2 || true
    exit 1
  fi
  printf '\n# Written by bootstrap.sh from GET /ilp/identity. This is a COPY of this\n# box%s connector sealing key, and a tenant compares it byte for byte.\nCONNECTOR_SEAL_KEY=%s\n' "'s" "$SEAL" >> .env
  echo "    recorded CONNECTOR_SEAL_KEY=${SEAL:0:10}… in .env"
  set -a; . ./.env; set +a
else
  echo "    CONNECTOR_SEAL_KEY is already in .env — kept"
fi

echo "==> [6/9] Render config"
./render.sh

echo "==> [7/9] Pull and start"
# Every image is a pin. pull-images.sh pulls them all, and fails on a pin that
# will not pull, except the sha-0000000 placeholder, which it builds from this
# checkout instead (README § "How updates arrive").
./pull-images.sh
docker compose up -d

echo "==> [8/9] TLS"
if [ "$HIDDEN" = 1 ]; then
  echo "    none: a hidden box has no public name. The address is its own key."
elif ! ./init-letsencrypt.sh; then
  echo "FAILED: certificate issuance did not succeed (its message is above, naming the" >&2
  echo "likely cause). Everything up to here already applied. Fix it, then re-run:" >&2
  echo "  cd $(pwd) && ./init-letsencrypt.sh" >&2
  exit 1
fi

echo "==> [9/9] The auto-apply and check timers"
# The box follows the tracked branch from here on: every five minutes it
# fast-forwards, re-renders and applies. ExecStart is absolute, so the unit
# only works from the checkout path it names — README § "Standing one up"
# clones to /root/provider for exactly that reason.
#
# And every five minutes `toon-provider status --check` asks whether anything
# needs a person (TOON_Network#172, ADR 0029 "Alerts are an exit code"): a
# Liveness close to expiry, a relay refusing writes, the publisher's runway
# short, the sealing key mismatched, the settlement key low on SOL. Each
# problem is a line in `journalctl -u toon-provider-check`, and a failed run
# is in `systemctl --failed`. auto-apply.sh keeps both units current.
install -m 644 toon-auto-apply.service /etc/systemd/system/toon-auto-apply.service
install -m 644 toon-auto-apply.timer   /etc/systemd/system/toon-auto-apply.timer
install -m 644 toon-provider-check.service /etc/systemd/system/toon-provider-check.service
install -m 644 toon-provider-check.timer   /etc/systemd/system/toon-provider-check.timer
systemctl daemon-reload
systemctl enable --now toon-auto-apply.timer
systemctl enable --now toon-provider-check.timer

echo
if [ "$HIDDEN" = 1 ]; then
  echo "hidden provider box up."
  echo "  paid ILP edge : http://${HIDDEN_ADDRESS}/ilp          (through anon only)"
  echo "  sealing key   : http://${HIDDEN_ADDRESS}/ilp/identity"
  echo "  workloads     : each lease at an .anyone address of its own"
  echo
  echo "The address is only reachable once the daemon has bootstrapped and published"
  echo "its descriptor: \`docker compose logs anon | grep Bootstrapped\`."
else
  echo "provider box up."
  echo "  paid ILP edge : https://proxy.provider.${DOMAIN}/ilp"
  echo "  sealing key   : https://proxy.provider.${DOMAIN}/ilp/identity"
  echo "  health        : https://provider.${DOMAIN}/health"
  echo "  workloads     : ${PUBLIC_IP}:40000-40099 (ssh), ${PUBLIC_IP}:41000-42599 (published)"
fi
echo
echo "Check it works:  docker compose exec provider toon-provider status"
echo
echo "The Profile, the Listings and the Liveness are published by"
echo "directory-publisher. If they do not appear on the relay, that container's"
echo "log is where the reason is — it is the one thing here that spends money."
