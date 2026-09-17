#!/bin/sh
set -eu

for template in /etc/nginx/templates/default.http.conf /etc/nginx/templates/default.https.conf; do
  append_count="$(grep -Fc 'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;' "$template" || true)"
  replace_count="$(grep -Fc 'proxy_set_header X-Forwarded-For $remote_addr;' "$template" || true)"
  directive_count="$(grep -Ec '^[[:space:]]*proxy_set_header[[:space:]]+X-Forwarded-For[[:space:]]+' "$template" || true)"
  [ "$directive_count" -eq 6 ] || { echo "Unexpected X-Forwarded-For directive count in $template" >&2; exit 1; }
  if [ "$append_count" -eq 6 ] && [ "$replace_count" -eq 0 ]; then
    sed 's/proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;/proxy_set_header X-Forwarded-For $remote_addr;/g' "$template" > "$template.root"
    mv "$template.root" "$template"
  elif [ "$append_count" -ne 0 ] || [ "$replace_count" -ne 6 ]; then
    echo "Unexpected X-Forwarded-For contract in $template" >&2
    exit 1
  fi
  [ "$(grep -Fc 'proxy_set_header X-Forwarded-For $remote_addr;' "$template" || true)" -eq 6 ]
  ! grep -Fq 'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;' "$template"
done

exec /usr/local/bin/nginx-entrypoint.sh
