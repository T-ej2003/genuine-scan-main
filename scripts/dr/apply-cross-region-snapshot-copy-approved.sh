#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root
require_command aws

confirm="${CONFIRM_SNAPSHOT_COPY:-}"
source_region="${SOURCE_REGION:-eu-west-2}"
target_region="${TARGET_REGION:-}"
source_snapshot="${SOURCE_SNAPSHOT_IDENTIFIER:-}"
source_snapshot_arn="${SOURCE_SNAPSHOT_ARN:-}"
target_snapshot="${TARGET_SNAPSHOT_IDENTIFIER:-}"
target_kms_key="${TARGET_KMS_KEY_ID:-}"

if [ "$confirm" != "I_APPROVE_CROSS_REGION_SNAPSHOT_COPY" ]; then
  echo "Refusing snapshot copy. Set CONFIRM_SNAPSHOT_COPY=I_APPROVE_CROSS_REGION_SNAPSHOT_COPY after approval." >&2
  exit 2
fi

missing=0
[ -n "$source_region" ] || { print_missing SOURCE_REGION; missing=1; }
[ -n "$target_region" ] || { print_missing TARGET_REGION; missing=1; }
if [ -z "$source_snapshot" ] && [ -z "$source_snapshot_arn" ]; then
  echo "Missing SOURCE_SNAPSHOT_IDENTIFIER or SOURCE_SNAPSHOT_ARN." >&2
  missing=1
fi
[ -n "$target_snapshot" ] || { print_missing TARGET_SNAPSHOT_IDENTIFIER; missing=1; }
[ "$missing" -eq 0 ] || exit 2

case "$target_snapshot" in
  *prod*|*primary*)
    echo "Refusing target snapshot identifier that looks like production/primary: $target_snapshot" >&2
    exit 2
    ;;
esac

create_artifact_dir
log_file="$DR_ARTIFACT_DIR/cross-region-snapshot-copy-approved.log"
source_snapshot_arg="${source_snapshot_arn:-$source_snapshot}"

run_copy() {
  echo "Timestamp: $DR_TIMESTAMP"
  echo "Source region: $source_region"
  echo "Target region: $target_region"
  echo "Source snapshot: $source_snapshot_arg"
  echo "Target snapshot: $target_snapshot"
  if [ -n "$target_kms_key" ]; then
    echo "Target KMS key provided: yes"
  else
    echo "Target KMS key provided: no"
  fi
  echo
  echo "=== copying DB snapshot to target region ==="
  set -- aws rds copy-db-snapshot \
    --source-region "$source_region" \
    --region "$target_region" \
    --source-db-snapshot-identifier "$source_snapshot_arg" \
    --target-db-snapshot-identifier "$target_snapshot" \
    --tags Key=Project,Value=MSCQR Key=Purpose,Value=DR Key=CreatedBy,Value=GitHubActionsOrOperator
  if [ -n "$target_kms_key" ]; then
    set -- "$@" --kms-key-id "$target_kms_key"
  fi
  "$@"
  echo
  echo "Monitor command:"
  echo "aws rds describe-db-snapshots --region '$target_region' --db-snapshot-identifier '$target_snapshot'"
}

set +e
run_copy > "$log_file" 2>&1
status="$?"
set -e

/bin/cat "$log_file"
exit "$status"
