#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

usage() {
  echo "Usage: scripts/dr/rollback-standby-db-env.sh <mumbai|capetown> <backup_path>" >&2
}

target="${1:-}"
backup_path="${2:-}"

case "$target" in
  mumbai|capetown) ;;
  *)
    usage
    exit 2
    ;;
esac

case "$backup_path" in
  /home/ubuntu/genuine-scan-main/backend/.env.backup.dr-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;;
  *)
    echo "Backup path must be a timestamped backend env backup from the recovered DB test." >&2
    usage
    exit 2
    ;;
esac

require_repo_root
require_command ansible-playbook

if [ ! -f ops/deploy/inventory.ini ]; then
  echo "Missing ops/deploy/inventory.ini. Configure local standby inventory outside Git." >&2
  exit 2
fi

create_artifact_dir
log_file="$DR_ARTIFACT_DIR/standby-db-env-rollback-$target.log"

echo "Rolling back standby DB env for $target."
echo "Backup path: $backup_path"

run_logged "$log_file" \
  ansible-playbook \
    -i ops/deploy/inventory.ini \
    ops/deploy/rollback-standby-db-env.yml \
    --limit "$target" \
    -e "backup_file_path=$backup_path"

echo "Evidence log: $log_file"
