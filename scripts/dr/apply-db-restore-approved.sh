#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root

confirm="${CONFIRM_DB_RESTORE:-}"
target_region="${TARGET_REGION:-}"
snapshot_identifier="${SNAPSHOT_IDENTIFIER:-}"
source_db="${SOURCE_DB_IDENTIFIER:-}"
recovery_point="${RECOVERY_POINT:-}"
target_db="${TARGET_DB_IDENTIFIER:-}"

if [ "$confirm" != "I_APPROVE_DB_RESTORE_TO_RECOVERY_TARGET" ]; then
  echo "Refusing DB restore. Set CONFIRM_DB_RESTORE=I_APPROVE_DB_RESTORE_TO_RECOVERY_TARGET after approval." >&2
  exit 2
fi

missing=0
[ -n "$target_region" ] || { print_missing TARGET_REGION; missing=1; }
[ -n "$target_db" ] || { print_missing TARGET_DB_IDENTIFIER; missing=1; }
if [ -z "$snapshot_identifier" ] && [ -z "$source_db" ]; then
  echo "Missing SNAPSHOT_IDENTIFIER or SOURCE_DB_IDENTIFIER." >&2
  missing=1
fi
if [ -n "$source_db" ] && [ -z "$recovery_point" ]; then
  echo "RECOVERY_POINT is required with SOURCE_DB_IDENTIFIER." >&2
  missing=1
fi
[ "$missing" -eq 0 ] || exit 2

target_db_lc="$(printf '%s' "$target_db" | /usr/bin/tr '[:upper:]' '[:lower:]')"
case "$target_db_lc" in
  primary|production|prod|*-primary|primary-*|*-production|production-*|*-prod|prod-*)
    echo "Refusing restore target that looks like production primary: $target_db" >&2
    exit 2
    ;;
esac

case "$target_db_lc" in
  *recovery*|*restore*|*dr*) ;;
  *)
    echo "TARGET_DB_IDENTIFIER must clearly indicate a recovery target, for example include dr, restore, or recovery." >&2
    exit 2
    ;;
esac

require_command aws
create_artifact_dir
log_file="$DR_ARTIFACT_DIR/db-restore-approved.log"

set +e
{
  echo "Timestamp: $DR_TIMESTAMP"
  echo "Target region: $target_region"
  echo "Target DB: $target_db"
  echo
  echo "=== verifying target DB does not already exist ==="
  if aws rds describe-db-instances --region "$target_region" --db-instance-identifier "$target_db" >/tmp/mscqr-dr-target-db.json 2>/tmp/mscqr-dr-target-db.err; then
    echo "Target DB already exists. Refusing to overwrite: $target_db"
    exit 2
  fi
  /bin/rm -f /tmp/mscqr-dr-target-db.json /tmp/mscqr-dr-target-db.err

  if [ -n "$snapshot_identifier" ]; then
    echo "=== restoring new DB instance from snapshot ==="
    aws rds restore-db-instance-from-db-snapshot \
      --region "$target_region" \
      --db-instance-identifier "$target_db" \
      --db-snapshot-identifier "$snapshot_identifier" \
      --no-publicly-accessible
  else
    echo "=== restoring new DB instance to point in time ==="
    aws rds restore-db-instance-to-point-in-time \
      --region "$target_region" \
      --source-db-instance-identifier "$source_db" \
      --target-db-instance-identifier "$target_db" \
      --restore-time "$recovery_point" \
      --no-publicly-accessible
  fi

  echo
  echo "Next steps:"
  echo "1. Wait for the new recovery target to become available."
  echo "2. Validate network access from the approved standby region."
  echo "3. Update standby app database secrets through the approved secret process."
  echo "4. Run standby health checks and application journey checks before any DNS change."
} > "$log_file" 2>&1
status="$?"
set -e

/bin/cat "$log_file"
exit "$status"
