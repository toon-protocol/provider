#!/usr/bin/env bash
# Render the files that carry deployment-specific values.
#
#   provider.toml.template    -> provider.toml              (0600 — A SECRET)
#   connector.toml.template   -> connector.toml             (paths, no secrets)
#   .env OPERATOR_BEARER_TOKEN-> operator-bearer.token       (0600 — a secret)
#   .env OPERATOR_WRITE_KEY   -> operator-write.keys         (0600 — public keys)
#   nginx/node.conf.template  -> nginx/conf.d/node.conf
#
# Every output is gitignored. Edit the templates.
#
# envsubst is given an EXPLICIT variable list. Without one it would substitute
# every $NAME it sees, and the nginx template contains nginx variables ($host,
# $upstream, $binary_remote_addr) that must survive to the rendered file.
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] || { echo "Missing .env — copy .env.example and fill it in." >&2; exit 1; }
set -a; . ./.env; set +a

: "${DOMAIN:?set DOMAIN in .env}"
: "${PROVIDER_NAME:?set PROVIDER_NAME in .env}"
: "${PUBLIC_IP:?set PUBLIC_IP in .env (this box public IPv4 — where tenants reach their workloads)}"
: "${NOSTR_PRIVATE_KEY:?set NOSTR_PRIVATE_KEY in .env (openssl rand -hex 32)}"
: "${RELAY_WS:?set RELAY_WS in .env (the relay READ url this provider publishes to)}"
: "${OPERATOR_BEARER_TOKEN:?set OPERATOR_BEARER_TOKEN in .env (openssl rand -hex 32)}"
: "${OPERATOR_WRITE_KEY:?set OPERATOR_WRITE_KEY in .env (the ed25519 public key allowed to sign operator writes)}"
: "${CERT_NAME:=proxy.provider.${DOMAIN}}"
export CERT_NAME

# ── The sealing key, which nothing here can invent ───────────────────────────
# A tenant seals its spawn to the key this box's connector answers with, and
# refuses to proceed if the Profile names a different one (ADR 0011). So the
# value below is not a setting: it is a COPY of a fact, and the only correct
# way to get it is to read it off the connector.
#
# bootstrap.sh reads it from `GET /ilp/identity` and writes it into .env, so
# nobody transcribes it by hand. Refuse rather than render a Profile that would
# be rejected by every tenant that read it.
if [ -z "${CONNECTOR_SEAL_KEY:-}" ]; then
  echo "CONNECTOR_SEAL_KEY is not set in .env." >&2
  echo >&2
  echo "It is this box's connector's own sealing key, copied verbatim — a tenant" >&2
  echo "compares it byte for byte against GET /ilp/identity before it will spawn" >&2
  echo "anything here (ADR 0011). Start the connector and read it off:" >&2
  echo >&2
  echo "  docker compose up -d provider-connector" >&2
  echo "  curl -s http://127.0.0.1:4000/ilp/identity" >&2
  echo >&2
  echo "then put its .publicKey (WITH the 0x) in .env as CONNECTOR_SEAL_KEY." >&2
  echo "./bootstrap.sh does all of that for you." >&2
  exit 1
fi

# ── provider.toml — the one rendered file in this fleet that IS a secret ─────
# It carries `nostr_private_key` inline: the identity that signs this
# provider's Profile, Listings, Liveness and Eviction Notices. Everything else
# here names key files; this one cannot, because the app takes the value.
envsubst '${PROVIDER_NAME} ${PUBLIC_IP} ${NOSTR_PRIVATE_KEY} ${DOMAIN} ${RELAY_WS} ${CONNECTOR_SEAL_KEY}' \
  < provider.toml.template > provider.toml
chmod 600 provider.toml

envsubst '${DOMAIN}' < connector.toml.template > connector.toml

# ── The operator surface's two credentials ───────────────────────────────────
#   operator-bearer.token   the shared secret that gates operator READS
#   operator-write.keys     the PUBLIC halves allowed to sign operator WRITES,
#                           one ed25519 key per line as 64 hex characters;
#                           `#` starts a comment
printf '%s\n' "${OPERATOR_BEARER_TOKEN}" > operator-bearer.token
{
  echo "# Public keys allowed to sign operator writes, one per line."
  echo "# Rendered from OPERATOR_WRITE_KEY in .env by ./render.sh."
  printf '%s\n' "${OPERATOR_WRITE_KEY}"
} > operator-write.keys

# None of these may be world-readable — but the connector container runs as uid
# 10001, and a root-owned 0600 file is unreadable to it ("failed to read config
# file: Permission denied", then a restart loop). Hand the connector's three to
# that uid rather than widening the mode. provider.toml stays root-owned: the
# provider image runs as root and it is the one file here that must not be
# readable by anything else.
chmod 600 connector.toml operator-bearer.token operator-write.keys
if [ "$(id -u)" = 0 ]; then
  chown "${CONNECTOR_UID:-10001}:${CONNECTOR_UID:-10001}" \
    connector.toml operator-bearer.token operator-write.keys
  chown 0:0 provider.toml
else
  echo "note: not running as root, so the rendered files stay owned by $(id -un)." >&2
  echo "      The connector container runs as uid 10001 and will not be able to" >&2
  echo "      read them. Fine for a local render; re-run as root on the box." >&2
fi

mkdir -p nginx/conf.d
envsubst '${DOMAIN} ${CERT_NAME}' \
  < nginx/node.conf.template > nginx/conf.d/node.conf

echo "rendered provider.toml (0600 — a secret), connector.toml, the operator"
echo "  credential files and nginx/conf.d/node.conf"
echo "  paid ILP edge       : https://proxy.provider.${DOMAIN}/ilp"
echo "  health              : https://provider.${DOMAIN}/health"
echo "  certificate lineage : ${CERT_NAME}"
