#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root

source_region="${SOURCE_REGION:-eu-west-2}"
target_region="${TARGET_REGION:-}"
source_snapshot="${SOURCE_SNAPSHOT_IDENTIFIER:-}"
target_snapshot="${TARGET_SNAPSHOT_IDENTIFIER:-}"
source_kms_key="${SOURCE_KMS_KEY_ID:-}"
target_kms_key="${TARGET_KMS_KEY_ID:-}"
target_standby="${TARGET_STANDBY:-}"

case "$target_standby:$target_region" in
  mumbai:ap-south-1|capetown:af-south-1|":") ;;
  mumbai:|"capetown:") ;;
  *)
    if [ -n "$target_standby" ] && [ -n "$target_region" ]; then
      echo "TARGET_REGION must be ap-south-1 for mumbai or af-south-1 for capetown." >&2
      exit 2
    fi
    ;;
esac

missing=0
[ -n "$target_region" ] || { print_missing TARGET_REGION; missing=1; }
[ -n "$source_snapshot" ] || { print_missing SOURCE_SNAPSHOT_IDENTIFIER; missing=1; }
[ -n "$target_snapshot" ] || { print_missing TARGET_SNAPSHOT_IDENTIFIER; missing=1; }
[ "$missing" -eq 0 ] || exit 2

create_artifact_dir
output_file="$DR_ARTIFACT_DIR/cross-region-snapshot-copy-plan.md"

snapshot_time="not available"
if command -v aws >/dev/null 2>&1; then
  snapshot_time="$(aws rds describe-db-snapshots --region "$source_region" --db-snapshot-identifier "$source_snapshot" --query 'DBSnapshots[0].SnapshotCreateTime' --output text 2>/dev/null || echo "not available")"
fi

{
  echo "# Cross-Region Snapshot Copy Plan"
  echo
  echo "Generated: $DR_TIMESTAMP"
  echo
  echo "## Inputs"
  echo
  echo "- Source region: $source_region"
  echo "- Target region: $target_region"
  echo "- Target standby: ${target_standby:-not provided}"
  echo "- Source snapshot identifier: $source_snapshot"
  echo "- Target snapshot identifier: $target_snapshot"
  echo "- Source KMS key: ${source_kms_key:-not provided}"
  echo "- Target KMS key: ${target_kms_key:-not provided}"
  echo "- Snapshot create time / RPO anchor: $snapshot_time"
  echo
  echo "## Operator Checklist"
  echo
  echo "- [ ] Confirm this snapshot satisfies the recovery point objective."
  echo "- [ ] Confirm target region is the selected standby region, not London."
  echo "- [ ] Confirm target snapshot identifier is new and clearly marked DR/recovery."
  echo "- [ ] Confirm encrypted snapshots have an approved target-region KMS key."
  echo "- [ ] Confirm no DNS or app cutover will happen from this step."
  echo
  echo "## Commented AWS CLI Example"
  echo
  echo '```bash'
  echo "# aws rds copy-db-snapshot \\"
  echo "#   --source-region '$source_region' \\"
  echo "#   --region '$target_region' \\"
  echo "#   --source-db-snapshot-identifier '$source_snapshot' \\"
  echo "#   --target-db-snapshot-identifier '$target_snapshot' \\"
  if [ -n "$target_kms_key" ]; then
    echo "#   --kms-key-id '$target_kms_key' \\"
  fi
  echo "#   --tags Key=Project,Value=MSCQR Key=Purpose,Value=DR Key=CreatedBy,Value=GitHubActionsOrOperator"
  echo '```'
  echo
  echo "This file is a plan only. It does not copy snapshots or mutate AWS."
} > "$output_file"

echo "Generated $output_file"
