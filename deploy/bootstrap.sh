#!/usr/bin/env bash
# Bring the provider box up from a fresh Ubuntu host. Idempotent — re-running
# it reconciles the box rather than rebuilding it.
#
#   ./bootstrap.sh
#
# Expects .env and the three connector key files to already be in this
# directory; see README.md § "Standing one up". Everything it installs is
# listed here, and it makes no changes outside this directory, ufw, docker,
# journald and the two systemd units it owns.
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] || { echo "Missing .env — copy .env.example and fill it in." >&2; exit 1; }
for f in signer.key settlement.key settlement-solana.key; do
  [ -f "$f" ] || { echo "Missing $f — see README.md § Standing one up." >&2; exit 1; }
done

set -a; . ./.env; set +a
: "${DOMAIN:?set DOMAIN in .env}"
: "${PUBLIC_IP:?set PUBLIC_IP in .env}"

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
apt-get update -y
apt-get install -y ufw curl gettext-base openssl jq
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp  comment 'SSH'
ufw allow 80/tcp  comment 'HTTP (ACME)'
ufw allow 443/tcp comment 'HTTPS'
ufw allow 40000:40099/tcp comment 'workload SSH forwards'
ufw allow 41000:42599/tcp comment 'workload published ports'
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

echo "==> [5/9] The connector, and the sealing key it alone knows"
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
  # A first render needs a value for envsubst even though the connector is
  # what will supply it; render only what the connector itself needs.
  envsubst '${DOMAIN}' < connector.toml.template > connector.toml
  printf '%s\n' "${OPERATOR_BEARER_TOKEN}" > operator-bearer.token
  printf '%s\n' "${OPERATOR_WRITE_KEY}" > operator-write.keys
  chmod 600 connector.toml operator-bearer.token operator-write.keys
  chown 10001:10001 connector.toml operator-bearer.token operator-write.keys
  docker compose up -d provider-connector

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
    echo "address is wrong. The log says which:" >&2
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

echo "==> [7/9] Build and start"
docker compose pull --ignore-buildable --ignore-pull-failures
docker compose build
docker compose up -d

echo "==> [8/9] TLS"
./init-letsencrypt.sh

echo "==> [9/9] The auto-apply timer"
# The box follows the tracked branch from here on: every five minutes it
# fast-forwards, re-renders and applies. ExecStart is absolute, so the unit
# only works from the checkout path it names — README § "Standing one up"
# clones to /root/provider for exactly that reason.
install -m 644 toon-auto-apply.service /etc/systemd/system/toon-auto-apply.service
install -m 644 toon-auto-apply.timer   /etc/systemd/system/toon-auto-apply.timer
systemctl daemon-reload
systemctl enable --now toon-auto-apply.timer

echo
echo "provider box up."
echo "  paid ILP edge : https://proxy.provider.${DOMAIN}/ilp"
echo "  sealing key   : https://proxy.provider.${DOMAIN}/ilp/identity"
echo "  health        : https://provider.${DOMAIN}/health"
echo "  workloads     : ${PUBLIC_IP}:40000-40099 (ssh), ${PUBLIC_IP}:41000-42599 (published)"
echo
echo "The Profile, the Listings and the Liveness are published by"
echo "directory-publisher. If they do not appear on the relay, that container's"
echo "log is where the reason is — it is the one thing here that spends money."
