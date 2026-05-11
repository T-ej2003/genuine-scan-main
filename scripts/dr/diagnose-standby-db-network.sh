#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

usage() {
  echo "Usage: DB_HOST=<host> DB_PORT=<port> scripts/dr/diagnose-standby-db-network.sh <mumbai|capetown>" >&2
}

target="${1:-${TARGET_STANDBY:-}}"
db_host="${DB_HOST:-}"
db_port="${DB_PORT:-5432}"

case "$target" in
  mumbai|capetown) ;;
  *)
    usage
    exit 2
    ;;
esac

case "$db_host" in
  *[!A-Za-z0-9._-]*|"")
    echo "DB_HOST must be a hostname containing only letters, digits, dots, underscores, or hyphens." >&2
    exit 2
    ;;
esac
case "$db_port" in
  *[!0-9]*|"")
    echo "DB_PORT must be numeric." >&2
    exit 2
    ;;
esac

require_repo_root
require_command ansible

if [ ! -f ops/deploy/inventory.ini ]; then
  echo "Missing ops/deploy/inventory.ini. Configure local standby inventory outside Git." >&2
  exit 2
fi

create_artifact_dir
log_file="$DR_ARTIFACT_DIR/standby-db-network-$target.log"

remote_script="
set -eu
echo 'Target standby: $target'
echo 'DB host: $db_host'
echo 'DB port: $db_port'
echo '=== DNS resolution ==='
getent hosts '$db_host'
echo '=== TCP connectivity ==='
if command -v nc >/dev/null 2>&1; then
  nc -vz -w 5 '$db_host' '$db_port'
else
  timeout 5 bash -c '</dev/tcp/$db_host/$db_port'
fi
"

run_logged "$log_file" \
  ansible -i ops/deploy/inventory.ini "$target" -m shell -a "$remote_script"

echo "Evidence log: $log_file"
