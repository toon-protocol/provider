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
  echo "::warning:: Certificate issuance failed (DNS may not have propagated yet)."
  echo "  Point the A-records at this box, then re-run with LETSENCRYPT_STAGING=0."
  seed_dummy
  "${DC[@]}" exec nginx nginx -s reload 2>/dev/null || true
fi
