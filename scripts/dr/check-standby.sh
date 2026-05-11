#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root
target="${1:-standby}"
validate_target "$target"
create_artifact_dir

log_file="$DR_ARTIFACT_DIR/standby-health-$target.log"
echo "Running standby health check for $target"
echo "Writing evidence to $log_file"

run_logged "$log_file" scripts/health-check-regions.sh "$target"
