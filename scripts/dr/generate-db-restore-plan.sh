#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root

source_db="${SOURCE_DB_IDENTIFIER:-}"
source_cluster="${SOURCE_CLUSTER_IDENTIFIER:-}"
target_region="${TARGET_REGION:-}"
recovery_point="${RECOVERY_POINT:-}"
snapshot_identifier="${SNAPSHOT_IDENTIFIER:-}"
target_db="${TARGET_DB_IDENTIFIER:-}"

missing=0
[ -n "$target_region" ] || { print_missing TARGET_REGION; missing=1; }
if [ -z "$snapshot_identifier" ] && [ -z "$source_db" ] && [ -z "$source_cluster" ]; then
  echo "Missing SNAPSHOT_IDENTIFIER, SOURCE_DB_IDENTIFIER, or SOURCE_CLUSTER_IDENTIFIER." >&2
  missing=1
fi
[ -n "$target_db" ] || { print_missing TARGET_DB_IDENTIFIER; missing=1; }
[ "$missing" -eq 0 ] || exit 2

create_artifact_dir
output_file="$DR_ARTIFACT_DIR/db-restore-plan.md"

{
  echo "# MSCQR DB Restore Plan"
  echo
  echo "Generated: $DR_TIMESTAMP"
  echo
  echo "## Inputs"
  echo
  echo "- Source DB identifier: ${source_db:-not used}"
  echo "- Source cluster identifier: ${source_cluster:-not used}"
  echo "- Target region: $target_region"
  echo "- Recovery point: ${recovery_point:-not used}"
  echo "- Snapshot identifier: ${snapshot_identifier:-not used}"
  echo "- Target DB identifier: $target_db"
  echo
  echo "## Operator Review Checklist"
  echo
  echo "- [ ] Incident commander approved recovery target creation."
  echo "- [ ] Recovery point satisfies the incident RPO."
  echo "- [ ] Target DB identifier is new and is not the production primary."
  echo "- [ ] Target region network, subnet group, and security groups are approved."
  echo "- [ ] Secrets will be updated through the approved secret process only."
  echo "- [ ] Standby application will be validated before any DNS move."
  echo "- [ ] Rollback owner and rollback DNS value are recorded."
  echo
  echo "## Commented AWS CLI Examples"
  echo
  echo '```bash'
  if [ -n "$snapshot_identifier" ]; then
    echo "# aws rds restore-db-instance-from-db-snapshot \\"
    echo "#   --region '$target_region' \\"
    echo "#   --db-instance-identifier '$target_db' \\"
    echo "#   --db-snapshot-identifier '$snapshot_identifier' \\"
    echo "#   --no-publicly-accessible"
  elif [ -n "$source_db" ]; then
    echo "# aws rds restore-db-instance-to-point-in-time \\"
    echo "#   --region '$target_region' \\"
    echo "#   --source-db-instance-identifier '$source_db' \\"
    echo "#   --target-db-instance-identifier '$target_db' \\"
    if [ -n "$recovery_point" ]; then
      echo "#   --restore-time '$recovery_point' \\"
    else
      echo "#   --use-latest-restorable-time \\"
    fi
    echo "#   --no-publicly-accessible"
  fi
  if [ -n "$source_cluster" ]; then
    echo "# aws rds restore-db-cluster-to-point-in-time \\"
    echo "#   --region '$target_region' \\"
    echo "#   --source-db-cluster-identifier '$source_cluster' \\"
    echo "#   --db-cluster-identifier '$target_db' \\"
    if [ -n "$recovery_point" ]; then
      echo "#   --restore-to-time '$recovery_point'"
    else
      echo "#   --use-latest-restorable-time"
    fi
  fi
  echo '```'
  echo
  echo "## Non-Goals"
  echo
  echo "This plan does not modify primary production, delete databases, overwrite an existing DB, or perform failover."
} > "$output_file"

echo "Generated $output_file"
