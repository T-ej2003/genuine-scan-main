#!/bin/sh
set -eu

for template in /etc/nginx/templates/default.http.conf /etc/nginx/templates/default.https.conf; do
  grep -q 'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;' "$template"
  sed 's/proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;/proxy_set_header X-Forwarded-For $remote_addr;/g' "$template" > "$template.root"
  mv "$template.root" "$template"
done

exec /usr/local/bin/nginx-entrypoint.sh
