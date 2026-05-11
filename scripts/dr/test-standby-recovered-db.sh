#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

usage() {
  echo "Usage: scripts/dr/test-standby-recovered-db.sh <mumbai|capetown>" >&2
  echo "Required env: RECOVERED_DB_HOST RECOVERED_DB_PORT RECOVERED_DB_NAME RECOVERED_DB_USER RECOVERED_DB_PASSWORD" >&2
}

target="${1:-}"
case "$target" in
  mumbai|capetown) ;;
  *)
    usage
    exit 2
    ;;
esac

missing=0
for name in RECOVERED_DB_HOST RECOVERED_DB_PORT RECOVERED_DB_NAME RECOVERED_DB_USER RECOVERED_DB_PASSWORD; do
  eval "value=\${$name:-}"
  if [ -z "$value" ]; then
    print_missing "$name"
    missing=1
  fi
done
[ "$missing" -eq 0 ] || exit 2

require_repo_root
require_command ansible-playbook

if [ ! -f ops/deploy/inventory.ini ]; then
  echo "Missing ops/deploy/inventory.ini. Configure local standby inventory outside Git." >&2
  exit 2
fi

create_artifact_dir
log_file="$DR_ARTIFACT_DIR/standby-recovered-db-test-$target.log"

echo "Running standby recovered DB connection test for $target."
echo "Recovered DB host: $RECOVERED_DB_HOST"
echo "Recovered DB port: $RECOVERED_DB_PORT"
echo "Recovered DB name: $RECOVERED_DB_NAME"
echo "Recovered DB password is provided through environment and will not be printed."

run_logged "$log_file" env RECOVERED_DB_PASSWORD="$RECOVERED_DB_PASSWORD" \
  ansible-playbook \
    -i ops/deploy/inventory.ini \
    ops/deploy/test-standby-recovered-db.yml \
    --limit "$target" \
    -e "recovered_db_host=$RECOVERED_DB_HOST" \
    -e "recovered_db_port=$RECOVERED_DB_PORT" \
    -e "recovered_db_name=$RECOVERED_DB_NAME" \
    -e "recovered_db_user=$RECOVERED_DB_USER" \
    -e "recovered_db_password_env_var_name=RECOVERED_DB_PASSWORD"

echo "Evidence log: $log_file"
