#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root
require_command aws

confirm="${CONFIRM_DR_SNAPSHOT_CLEANUP:-}"
target_region="${TARGET_REGION:-${AWS_REGION:-}}"
target_snapshot="${TARGET_SNAPSHOT_IDENTIFIER:-}"

if [ "$confirm" != "I_APPROVE_DR_SNAPSHOT_CLEANUP" ]; then
  echo "Refusing DR snapshot cleanup. Set CONFIRM_DR_SNAPSHOT_CLEANUP=I_APPROVE_DR_SNAPSHOT_CLEANUP after approval." >&2
  exit 2
fi

missing=0
[ -n "$target_region" ] || { print_missing TARGET_REGION; missing=1; }
[ -n "$target_snapshot" ] || { print_missing TARGET_SNAPSHOT_IDENTIFIER; missing=1; }
[ "$missing" -eq 0 ] || exit 2

snapshot_lc="$(printf '%s' "$target_snapshot" | /usr/bin/tr '[:upper:]' '[:lower:]')"

case "$snapshot_lc" in
  rds:*)
    echo "Refusing to delete automated RDS snapshot identifier: $target_snapshot" >&2
    exit 2
    ;;
esac

case "$snapshot_lc" in
  *dr*|*copy*|*restore*|*recovery*|*test*) ;;
  *)
    echo "TARGET_SNAPSHOT_IDENTIFIER must include dr, copy, restore, recovery, or test for cleanup." >&2
    exit 2
    ;;
esac

case "$snapshot_lc" in
  *prod*|*production*|*primary*|*london*|*live*)
    case "$snapshot_lc" in
      *dr*|*copy*|*restore*|*recovery*|*test*) ;;
      *)
        echo "Refusing production-looking snapshot identifier without clear DR/recovery/test marker: $target_snapshot" >&2
        exit 2
        ;;
    esac
    ;;
esac

create_artifact_dir
log_file="$DR_ARTIFACT_DIR/dr-snapshot-cleanup-approved.log"

run_cleanup() {
  echo "Timestamp: $DR_TIMESTAMP"
  echo "Target region: $target_region"
  echo "Target DR snapshot: $target_snapshot"
  echo
  echo "=== describing target DR snapshot before cleanup ==="
  aws rds describe-db-snapshots --region "$target_region" --db-snapshot-identifier "$target_snapshot" > "$DR_ARTIFACT_DIR/dr-snapshot-before-delete.json"
  snapshot_type="$(aws rds describe-db-snapshots --region "$target_region" --db-snapshot-identifier "$target_snapshot" --query 'DBSnapshots[0].SnapshotType' --output text)"
  snapshot_status="$(aws rds describe-db-snapshots --region "$target_region" --db-snapshot-identifier "$target_snapshot" --query 'DBSnapshots[0].Status' --output text)"
  echo "Snapshot type: $snapshot_type"
  echo "Snapshot status: $snapshot_status"
  if [ "$snapshot_type" != "manual" ]; then
    echo "Refusing to delete non-manual snapshot type: $snapshot_type" >&2
    return 2
  fi
  echo
  echo "=== deleting approved DR snapshot ==="
  aws rds delete-db-snapshot \
    --region "$target_region" \
    --db-snapshot-identifier "$target_snapshot"
  echo
  echo "Monitor command:"
  echo "aws rds describe-db-snapshots --region '$target_region' --db-snapshot-identifier '$target_snapshot'"
}

set +e
run_cleanup > "$log_file" 2>&1
status="$?"
set -e

/bin/cat "$log_file"
exit "$status"
