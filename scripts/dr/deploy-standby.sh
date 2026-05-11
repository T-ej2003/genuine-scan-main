#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root
target="${1:-standby}"
validate_target "$target"
create_artifact_dir

log_file="$DR_ARTIFACT_DIR/standby-deploy-$target.log"
echo "Deploying standby target $target through the existing safe deploy wrapper"
echo "Writing evidence to $log_file"

set +e
{
  echo "=== deploy $target ==="
  scripts/deploy-standby.sh "$target"
  deploy_status="$?"
  echo "=== deploy exit: $deploy_status ==="
  if [ "$deploy_status" -ne 0 ]; then
    exit "$deploy_status"
  fi

  echo "=== post-deploy health $target ==="
  scripts/health-check-regions.sh "$target"
} > "$log_file" 2>&1
status="$?"
set -e

/bin/cat "$log_file"
exit "$status"
