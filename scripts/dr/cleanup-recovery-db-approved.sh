#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root
require_command aws

confirm="${CONFIRM_RECOVERY_DB_CLEANUP:-}"
target_region="${TARGET_REGION:-}"
target_db="${TARGET_DB_IDENTIFIER:-}"
final_snapshot="${FINAL_SNAPSHOT_IDENTIFIER:-}"
confirm_skip_final="${CONFIRM_SKIP_FINAL_SNAPSHOT:-}"

if [ "$confirm" != "I_APPROVE_RECOVERY_DB_CLEANUP" ]; then
  echo "Refusing recovery DB cleanup. Set CONFIRM_RECOVERY_DB_CLEANUP=I_APPROVE_RECOVERY_DB_CLEANUP after approval." >&2
  exit 2
fi

missing=0
[ -n "$target_region" ] || { print_missing TARGET_REGION; missing=1; }
[ -n "$target_db" ] || { print_missing TARGET_DB_IDENTIFIER; missing=1; }
[ "$missing" -eq 0 ] || exit 2

target_db_lc="$(printf '%s' "$target_db" | /usr/bin/tr '[:upper:]' '[:lower:]')"
if [ "$target_db_lc" = "mscqr-prod-db" ]; then
  echo "Refusing cleanup for production DB identifier: $target_db" >&2
  exit 2
fi
case "$target_db_lc" in
  *dr*|*restore*|*test*|*recovery*) ;;
  *)
    echo "TARGET_DB_IDENTIFIER must include dr, restore, test, or recovery for cleanup." >&2
    exit 2
    ;;
esac

if [ -z "$final_snapshot" ] && [ "$confirm_skip_final" != "I_APPROVE_SKIP_FINAL_SNAPSHOT" ]; then
  echo "Set FINAL_SNAPSHOT_IDENTIFIER or CONFIRM_SKIP_FINAL_SNAPSHOT=I_APPROVE_SKIP_FINAL_SNAPSHOT." >&2
  exit 2
fi

create_artifact_dir
log_file="$DR_ARTIFACT_DIR/recovery-db-cleanup-approved.log"

run_cleanup() {
  echo "Timestamp: $DR_TIMESTAMP"
  echo "Target region: $target_region"
  echo "Target recovery DB: $target_db"
  if [ -n "$final_snapshot" ]; then
    echo "Final snapshot identifier: $final_snapshot"
  else
    echo "Final snapshot: intentionally skipped by explicit approval"
  fi
  echo
  echo "=== describing target recovery DB before cleanup ==="
  aws rds describe-db-instances --region "$target_region" --db-instance-identifier "$target_db"
  echo
  echo "=== deleting approved recovery DB target ==="
  if [ -n "$final_snapshot" ]; then
    aws rds delete-db-instance \
      --region "$target_region" \
      --db-instance-identifier "$target_db" \
      --final-db-snapshot-identifier "$final_snapshot"
  else
    aws rds delete-db-instance \
      --region "$target_region" \
      --db-instance-identifier "$target_db" \
      --skip-final-snapshot
  fi
  echo
  echo "Monitor command:"
  echo "aws rds describe-db-instances --region '$target_region' --db-instance-identifier '$target_db'"
}

set +e
run_cleanup > "$log_file" 2>&1
status="$?"
set -e

/bin/cat "$log_file"
exit "$status"
