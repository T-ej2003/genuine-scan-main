#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

DOCKER_BIN="${DOCKER_BIN:-docker}"
CERTBOT_IMAGE="${MSCQR_CERTBOT_IMAGE:-certbot/certbot}"
FRONTEND_SERVICE="${MSCQR_FRONTEND_SERVICE:-frontend}"
DRY_RUN="${MSCQR_CERTBOT_DRY_RUN:-false}"
RESTART_FRONTEND="${MSCQR_RESTART_FRONTEND:-true}"

WEBROOT_DIR="$PROJECT_ROOT/deploy/certbot/www"
CERTS_DIR="$PROJECT_ROOT/deploy/certbot/conf"

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

echo "MSCQR Let's Encrypt renewal helper"
echo "Project root: $PROJECT_ROOT"

RENEW_FLAGS="--quiet"
if [ "$DRY_RUN" = "true" ]; then
  RENEW_FLAGS="$RENEW_FLAGS --dry-run"
fi

echo "Running certbot renew $RENEW_FLAGS"
(
  cd "$PROJECT_ROOT"
  # shellcheck disable=SC2086
  "$DOCKER_BIN" run --rm \
    -v "$WEBROOT_DIR:/var/www/certbot" \
    -v "$CERTS_DIR:/etc/letsencrypt" \
    "$CERTBOT_IMAGE" renew --webroot \
    -w /var/www/certbot \
    $RENEW_FLAGS
)

if [ "$DRY_RUN" = "true" ]; then
  echo "Dry run completed. Frontend restart skipped."
  exit 0
fi

if [ "$RESTART_FRONTEND" = "true" ]; then
  echo "Restarting frontend after renewal..."
  (
    cd "$PROJECT_ROOT"
    "$DOCKER_BIN" compose restart "$FRONTEND_SERVICE"
  )
fi

echo "Renewal command completed."
