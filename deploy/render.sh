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
#   ./render.sh                  everything
#   ./render.sh --connector-only everything EXCEPT provider.toml
#
# The second mode exists for one moment in bootstrap.sh: provider.toml cannot
# be rendered until the connector has said what its sealing key is, and the
# connector cannot say until it is running. So the connector's own files are
# rendered first, it is started alone, asked, and then everything is rendered
# properly. That is ONE renderer with two scopes rather than two renderers --
# the thing this script knows that a hand-rolled copy in bootstrap.sh kept
# forgetting is that the key files need their ownership fixed too.
#
# envsubst is given an EXPLICIT variable list. Without one it would substitute
# every $NAME it sees, and the nginx template contains nginx variables ($host,
# $upstream, $binary_remote_addr) that must survive to the rendered file.
set -euo pipefail
cd "$(dirname "$0")"

CONNECTOR_ONLY=0
case "${1:-}" in
  --connector-only) CONNECTOR_ONLY=1 ;;
  '') ;;
  *) echo "usage: ./render.sh [--connector-only]" >&2; exit 2 ;;
esac

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
if [ "$CONNECTOR_ONLY" = 0 ] && [ -z "${CONNECTOR_SEAL_KEY:-}" ]; then
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

# ── A directory where a file belongs ─────────────────────────────────────────
# docker answers a bind mount naming a path that does not exist by CREATING an
# empty directory there. Anything that starts the app before its config is
# rendered leaves one behind, and the app then dies on "read provider config
# at /etc/toon-provider/provider.toml: Is a directory" for the rest of time,
# because envsubst below cannot write over a directory either. An EMPTY one
# can only have come from that, so clear it; a non-empty one is somebody's
# work and is refused instead.
for path in provider.toml connector.toml; do
  [ -d "$path" ] || continue
  if rmdir "$path" 2>/dev/null; then
    echo "note: removed an empty directory at ./${path} — docker creates one when a" >&2
    echo "      bind mount names a file that has not been rendered yet." >&2
  else
    echo "./${path} is a directory and is not empty. It must be a file; something" >&2
    echo "other than this script put it there. Move it aside and re-run." >&2
    exit 1
  fi
done

# ── provider.toml — the one rendered file in this fleet that IS a secret ─────
# It carries `nostr_private_key` inline: the identity that signs this
# provider's Profile, Listings, Liveness and Eviction Notices. Everything else
# here names key files; this one cannot, because the app takes the value.
if [ "$CONNECTOR_ONLY" = 0 ]; then
  envsubst '${PROVIDER_NAME} ${PUBLIC_IP} ${NOSTR_PRIVATE_KEY} ${DOMAIN} ${RELAY_WS} ${CONNECTOR_SEAL_KEY}' \
    < provider.toml.template > provider.toml
  chmod 600 provider.toml
fi

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
#
# THE HAND-PLACED KEY FILES NEED THE SAME TREATMENT, and the fleet's runbooks
# have always said so as a manual step (connector#492's restart loop:
# "failed to read signer key_file at /app/data/signer.key: Permission denied").
# A step a human has to remember is a step a human forgets, and the failure is
# a container that restarts forever while everything around it looks fine.
# They are chmodded here too, so `openssl rand -hex 32 > signer.key` with a
# default umask is corrected rather than merely tolerated.
chmod 600 connector.toml operator-bearer.token operator-write.keys
for key in signer.key settlement.key settlement-solana.key; do
  [ -f "$key" ] && chmod 600 "$key"
done
if [ "$(id -u)" = 0 ]; then
  chown "${CONNECTOR_UID:-10001}:${CONNECTOR_UID:-10001}" \
    connector.toml operator-bearer.token operator-write.keys
  for key in signer.key settlement.key settlement-solana.key; do
    [ -f "$key" ] && chown "${CONNECTOR_UID:-10001}:${CONNECTOR_UID:-10001}" "$key"
  done
  [ "$CONNECTOR_ONLY" = 0 ] && chown 0:0 provider.toml
else
  echo "note: not running as root, so the rendered files stay owned by $(id -un)." >&2
  echo "      The connector container runs as uid 10001 and will not be able to" >&2
  echo "      read them. Fine for a local render; re-run as root on the box." >&2
fi

mkdir -p nginx/conf.d
envsubst '${DOMAIN} ${CERT_NAME}' \
  < nginx/node.conf.template > nginx/conf.d/node.conf

if [ "$CONNECTOR_ONLY" = 1 ]; then
  echo "rendered connector.toml, the operator credential files and"
  echo "  nginx/conf.d/node.conf — NOT provider.toml (--connector-only)"
else
  echo "rendered provider.toml (0600 — a secret), connector.toml, the operator"
  echo "  credential files and nginx/conf.d/node.conf"
fi
echo "  paid ILP edge       : https://proxy.provider.${DOMAIN}/ilp"
echo "  health              : https://provider.${DOMAIN}/health"
echo "  certificate lineage : ${CERT_NAME}"
