#!/usr/bin/env bash
# Issue or reuse the TLS certificate for this box, then reload nginx.
#
# Two names on one lineage:
#   proxy.provider.${DOMAIN}  the paid ILP edge
#   provider.${DOMAIN}        GET /health, and nothing else
#
# Idempotent and safe to re-run: if a valid, non-self-signed certificate that
# already covers both hostnames is present and outside the renewal window, it
# reuses it rather than spending a Let's Encrypt rate-limit slot.
#
# Run AFTER `docker compose up -d` (nginx must be able to serve the ACME
# challenge over port 80) and after DNS A-records point here.
set -euo pipefail
cd "$(dirname "$0")"

set -a; . ./.env; set +a
: "${DOMAIN:?set DOMAIN in .env}"
: "${PUBLIC_IP:?set PUBLIC_IP in .env}"
: "${LETSENCRYPT_EMAIL:?set LETSENCRYPT_EMAIL in .env}"

DC=(docker compose)
PRIMARY="proxy.provider.${DOMAIN}"
DOMAINS=("proxy.provider.${DOMAIN}" "provider.${DOMAIN}")
# The lineage directory name. Defaults to the primary hostname; override in
# .env when an existing box already has a certificate filed under an older
# name (renaming a lineage means re-issuing, which costs a rate-limit slot for
# no benefit while the existing certificate still covers both names).
CERT_NAME="${CERT_NAME:-${PRIMARY}}"
CERT_PATH="/etc/letsencrypt/live/${CERT_NAME}"
RENEW_WINDOW_DAYS="${RENEW_WINDOW_DAYS:-30}"

seed_dummy() {
  "${DC[@]}" run --rm --entrypoint sh certbot -c "
    mkdir -p '${CERT_PATH}' &&
    openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
      -keyout '${CERT_PATH}/privkey.pem' \
      -out    '${CERT_PATH}/fullchain.pem' \
      -subj '/CN=${PRIMARY}'"
}

existing_cert_ok() {
  local want_staging="0"
  [ "${LETSENCRYPT_STAGING:-1}" = "1" ] && want_staging="1"
  local sans
  sans="$(printf '%s\n' "${DOMAINS[@]}")"
  "${DC[@]}" run --rm --entrypoint sh certbot -c '
    set -e
    CERT="'"${CERT_PATH}"'/fullchain.pem"
    [ -s "$CERT" ] || exit 0
    openssl x509 -checkend "$(( '"${RENEW_WINDOW_DAYS}"' * 86400 ))" -noout -in "$CERT" >/dev/null 2>&1 || exit 0
    issuer="$(openssl x509 -issuer -noout -in "$CERT")"
    subj="$(openssl x509 -subject -noout -in "$CERT")"
    [ "$issuer" = "$(printf "%s" "$subj" | sed "s/^subject/issuer/")" ] && exit 0
    printf "%s" "$issuer" | grep -qi "Let'"'"'s Encrypt\|(STAGING)\|ACME\|R[0-9]\|E[0-9]" || exit 0
    is_staging=0
    printf "%s" "$issuer" | grep -qi "STAGING\|Fake LE" && is_staging=1
    [ "$is_staging" = "'"${want_staging}"'" ] || exit 0
    san="$(openssl x509 -ext subjectAltName -noout -in "$CERT" 2>/dev/null || openssl x509 -text -noout -in "$CERT")"
    san="$(printf "%s" "$san" | tr "," "\n" | tr -d " " | sed "s/\$/,/")"
    while IFS= read -r d; do
      [ -n "$d" ] || continue
      printf "%s\n" "$san" | grep -qF "DNS:$d," || exit 0
    done <<SANS
'"${sans}"'
SANS
    echo ok
  ' 2>/dev/null | tr -d '[:space:]'
}

# A warning, not a gate: certbot's own attempt below is the real test, and
# giving it the chance still tells the operator more (the exact hostname and
# the exact API/HTTP error) than refusing to try. But most HTTP-01 failures
# ARE just an A-record that has not propagated yet, and that is worth saying
# before spending an attempt on it, not only after.
warn_if_dns_wrong() {
  local d ip
  for d in "${DOMAINS[@]}"; do
    ip="$(getent ahostsv4 "$d" 2>/dev/null | awk '{print $1; exit}' || true)"
    if [ -z "$ip" ]; then
      echo "::warning:: ${d} does not resolve yet — issuance will fail until its A-record points at ${PUBLIC_IP}."
    elif [ "$ip" != "$PUBLIC_IP" ]; then
      echo "::warning:: ${d} resolves to ${ip}, not this box's PUBLIC_IP (${PUBLIC_IP}) — issuance will fail until the A-record is fixed."
    fi
  done
}

echo "==> Checking for an existing valid certificate (${CERT_NAME})"
if [ "$(existing_cert_ok)" = "ok" ]; then
  echo "==> Valid certificate found — reusing it, not re-issuing."
  "${DC[@]}" up -d nginx
  "${DC[@]}" exec nginx nginx -s reload 2>/dev/null || true
  exit 0
fi

echo "==> Seeding a self-signed certificate so nginx can start"
seed_dummy
"${DC[@]}" up -d nginx
"${DC[@]}" run --rm --entrypoint sh certbot -c \
  "rm -rf /etc/letsencrypt/live/${CERT_NAME} /etc/letsencrypt/archive/${CERT_NAME} /etc/letsencrypt/renewal/${CERT_NAME}.conf"

warn_if_dns_wrong

d_args=()
for d in "${DOMAINS[@]}"; do d_args+=(-d "$d"); done
staging_arg=""
[ "${LETSENCRYPT_STAGING:-1}" = "1" ] && staging_arg="--staging"

echo "==> Requesting a certificate (${staging_arg:-production})"
if "${DC[@]}" run --rm --entrypoint certbot certbot \
  certonly --webroot -w /var/www/certbot \
  $staging_arg \
  --cert-name "${CERT_NAME}" \
  "${d_args[@]}" \
  --email "${LETSENCRYPT_EMAIL}" \
  --rsa-key-size 2048 --agree-tos --no-eff-email --keep-until-expiring; then
  # Tolerant, like the other two reloads in this file, and for a reason worth
  # stating: under `set -e` in bootstrap.sh a failed reload aborted the WHOLE
  # bring-up at the TLS step — which silently skipped installing the
  # auto-apply timer, leaving a box that looked deployed and would never
  # update itself again. nginx is a container that can be mid-restart at this
  # moment; the certificate is on disk either way, and the reload loop in
  # docker-compose.yml picks it up within six hours regardless.
  "${DC[@]}" exec nginx nginx -s reload 2>/dev/null \
    || echo "::warning:: nginx would not reload; it will pick the new certificate up on its own within 6h."
  echo "Done.${staging_arg:+ STAGING certificate — re-run with LETSENCRYPT_STAGING=0 once DNS resolves.}"
else
  # A dummy is reseeded so nginx still answers something, but this script
  # itself must fail: a box serving no valid certificate is the
  # half-configured state worse than one that refused to come up at all
  # (TOON_Network#163), so it is not this script's place to call that "done".
  seed_dummy
  "${DC[@]}" exec nginx nginx -s reload 2>/dev/null || true
  echo "::error:: Certificate issuance failed." >&2
  echo "  Almost always: an A-record (${DOMAINS[*]}) does not resolve to this box (${PUBLIC_IP}) yet." >&2
  echo "  The certbot log above names the call that failed. Once the A-records are fixed," >&2
  echo "  re-run ./init-letsencrypt.sh." >&2
  exit 1
fi
