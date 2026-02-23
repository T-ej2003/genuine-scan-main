#!/bin/sh
set -eu

HTTP_CONF="/etc/nginx/templates/default.http.conf"
HTTPS_CONF="/etc/nginx/templates/default.https.conf"
TARGET_CONF="/etc/nginx/conf.d/default.conf"

CERT_PATH="${SSL_CERT_PATH:-/etc/letsencrypt/live/mscqr.com/fullchain.pem}"
KEY_PATH="${SSL_KEY_PATH:-/etc/letsencrypt/live/mscqr.com/privkey.pem}"
SSL_MODE="${SSL_ENABLED:-auto}"

use_https="false"
if [ "$SSL_MODE" = "true" ]; then
  use_https="true"
elif [ "$SSL_MODE" = "auto" ] && [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
  use_https="true"
fi

if [ "$use_https" = "true" ]; then
  cp "$HTTPS_CONF" "$TARGET_CONF"
  echo "Using HTTPS nginx config ($CERT_PATH)"
else
  cp "$HTTP_CONF" "$TARGET_CONF"
  echo "Using HTTP nginx config (certificate not found yet)"
fi

exec nginx -g "daemon off;"
