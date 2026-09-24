#!/usr/bin/env bash
# Every key this box needs, and every address it has to fund — before
# anything boots. Run it before ./bootstrap.sh, on a host with nothing on it
# yet: it needs bash and python3, which every Ubuntu release ships.
#
#   ./keys.sh init          generate every key file and .env secret that is
#                           missing; never replaces one that exists
#   ./keys.sh addresses     print every address to fund, in the format a
#                           faucet takes, and what to fund it with
#   ./keys.sh check-funded  ask the Solana RPC (a free read) whether the keys
#                           that must be funded are; bootstrap.sh runs this
#
# The derivations live in keys.py, beside this, and each is pinned to the
# component's own by tests/deploy_keys.rs. README.md § "Standing one up".
set -euo pipefail
cd "$(dirname "$0")"

command -v python3 >/dev/null 2>&1 || {
  echo "keys.sh needs python3: apt-get install -y python3-minimal" >&2
  exit 1
}

case "${1:-}" in
  init)
    if [ ! -f .env ]; then
      cp .env.example .env
      chmod 600 .env
      echo "    .env                     created from .env.example -- fill in the rest of it"
    fi
    ;;
  addresses|check-funded|derive) ;;
  *)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
    ;;
esac

[ -f .env ] || { echo "Missing .env — run ./keys.sh init first." >&2; exit 1; }
set -a; . ./.env; set +a
exec python3 keys.py provider "$@"
