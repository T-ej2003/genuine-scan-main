#!/bin/sh
set -eu

HTTP_CONF="/etc/nginx/templates/default.http.conf"
HTTPS_CONF="/etc/nginx/templates/default.https.conf"
TARGET_CONF="/etc/nginx/conf.d/default.conf"

CERT_PATH="${SSL_CERT_PATH:-/etc/letsencrypt/live/mscqr.com/fullchain.pem}"
KEY_PATH="${SSL_KEY_PATH:-/etc/letsencrypt/live/mscqr.com/privkey.pem}"
SSL_MODE="${SSL_ENABLED:-auto}"
BACKEND_UPSTREAM_RAW="${BACKEND_UPSTREAM:-http://backend:4000}"

case "$BACKEND_UPSTREAM_RAW" in
  http://*|https://*) ;;
  *://*)
    echo "Invalid BACKEND_UPSTREAM scheme. Use http:// or https://." >&2
    exit 1
    ;;
  *)
    BACKEND_UPSTREAM_RAW="http://$BACKEND_UPSTREAM_RAW"
    ;;
esac

BACKEND_UPSTREAM="${BACKEND_UPSTREAM_RAW%/}"
BACKEND_UPSTREAM_HOST_PATH="${BACKEND_UPSTREAM#http://}"
BACKEND_UPSTREAM_HOST_PATH="${BACKEND_UPSTREAM_HOST_PATH#https://}"
case "$BACKEND_UPSTREAM_HOST_PATH" in
  ""|*/*|*[\;\ \	\$]*)
    echo "Invalid BACKEND_UPSTREAM. Provide an origin only, for example http://backend:4000 or https://api.example.com." >&2
    exit 1
    ;;
esac

NGINX_RESOLVER="${NGINX_RESOLVER:-}"
if [ -z "$NGINX_RESOLVER" ]; then
  NGINX_RESOLVER="$(awk '/^nameserver[[:space:]]+[0-9.]+$/ { print $2; exit }' /etc/resolv.conf 2>/dev/null || true)"
fi
NGINX_RESOLVER="${NGINX_RESOLVER:-127.0.0.11}"

escape_sed_replacement() {
  printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}

sanitize_origin_for_log() {
  printf '%s' "$1" | sed -E 's#(https?://)[^/@]+@#\1[redacted]@#'
}

render_template() {
  template_path="$1"
  target_path="$2"
  backend_escaped="$(escape_sed_replacement "$BACKEND_UPSTREAM")"
  resolver_escaped="$(escape_sed_replacement "$NGINX_RESOLVER")"
  sed \
    -e "s|__BACKEND_UPSTREAM__|$backend_escaped|g" \
    -e "s|__NGINX_RESOLVER__|$resolver_escaped|g" \
    "$template_path" > "$target_path"
}

use_https="false"
if [ "$SSL_MODE" = "true" ]; then
  use_https="true"
elif [ "$SSL_MODE" = "auto" ] && [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
  use_https="true"
fi

if [ "$use_https" = "true" ]; then
  render_template "$HTTPS_CONF" "$TARGET_CONF"
  echo "Using HTTPS nginx config ($CERT_PATH)"
else
  render_template "$HTTP_CONF" "$TARGET_CONF"
  echo "Using HTTP nginx config (certificate not found yet)"
fi
echo "Using backend upstream: $(sanitize_origin_for_log "$BACKEND_UPSTREAM")"
echo "Using nginx resolver: $NGINX_RESOLVER"

nginx -t

exec nginx -g "daemon off;"
