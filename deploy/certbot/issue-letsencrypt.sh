#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

DOCKER_BIN="${DOCKER_BIN:-docker}"
DOMAIN_ROOT="${MSCQR_DOMAIN_ROOT:-mscqr.com}"
DOMAIN_WWW="${MSCQR_DOMAIN_WWW:-www.mscqr.com}"
CERTBOT_EMAIL="${MSCQR_LE_EMAIL:-administration@mscqr.com}"
CERTBOT_IMAGE="${MSCQR_CERTBOT_IMAGE:-certbot/certbot}"
FRONTEND_SERVICE="${MSCQR_FRONTEND_SERVICE:-frontend}"
BOOTSTRAP_HTTP="${MSCQR_BOOTSTRAP_HTTP:-false}"
RESTART_FRONTEND="${MSCQR_RESTART_FRONTEND:-true}"

WEBROOT_DIR="$PROJECT_ROOT/deploy/certbot/www"
CERTS_DIR="$PROJECT_ROOT/deploy/certbot/conf"
CERT_FILE="$CERTS_DIR/live/$DOMAIN_ROOT/fullchain.pem"
KEY_FILE="$CERTS_DIR/live/$DOMAIN_ROOT/privkey.pem"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_tools() {
  command -v "$DOCKER_BIN" >/dev/null 2>&1 || fail "docker is required on this host."
  "$DOCKER_BIN" compose version >/dev/null 2>&1 || fail "docker compose is required on this host."
}

mkdir -p "$WEBROOT_DIR" "$CERTS_DIR"
require_tools

echo "MSCQR Let's Encrypt issue helper"
echo "Project root: $PROJECT_ROOT"
echo "Domains: $DOMAIN_ROOT, $DOMAIN_WWW"
echo "Email: $CERTBOT_EMAIL"

if [ "$BOOTSTRAP_HTTP" = "true" ]; then
  echo "Bootstrapping MSCQR in HTTP mode first..."
  (
    cd "$PROJECT_ROOT"
    "$DOCKER_BIN" compose up -d --build
  )
fi

echo "Requesting Let's Encrypt certificate via webroot challenge..."
(
  cd "$PROJECT_ROOT"
  "$DOCKER_BIN" run --rm \
    -v "$WEBROOT_DIR:/var/www/certbot" \
    -v "$CERTS_DIR:/etc/letsencrypt" \
    "$CERTBOT_IMAGE" certonly --webroot \
    -w /var/www/certbot \
    -d "$DOMAIN_ROOT" -d "$DOMAIN_WWW" \
    --email "$CERTBOT_EMAIL" \
    --agree-tos --no-eff-email
)

[ -f "$CERT_FILE" ] || fail "certificate was not created at $CERT_FILE"
[ -f "$KEY_FILE" ] || fail "private key was not created at $KEY_FILE"

if [ "$RESTART_FRONTEND" = "true" ]; then
  echo "Restarting frontend so nginx switches to HTTPS mode..."
  (
    cd "$PROJECT_ROOT"
    "$DOCKER_BIN" compose restart "$FRONTEND_SERVICE"
  )
fi

echo
echo "TLS files are present."
echo "Verify with:"
echo "  curl -I https://$DOMAIN_ROOT"
echo "  curl -I https://$DOMAIN_WWW"
echo "  $DOCKER_BIN compose logs $FRONTEND_SERVICE --tail 50"
