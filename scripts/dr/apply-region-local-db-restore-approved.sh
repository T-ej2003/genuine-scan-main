#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root
require_command aws

confirm="${CONFIRM_REGION_LOCAL_DB_RESTORE:-}"
target_standby="${TARGET_STANDBY:-}"
target_region="${TARGET_REGION:-}"
snapshot_identifier="${SNAPSHOT_IDENTIFIER:-}"
target_db="${TARGET_DB_IDENTIFIER:-}"
db_subnet_group_name="${DB_SUBNET_GROUP_NAME:-}"
db_vpc_security_group_ids="${DB_VPC_SECURITY_GROUP_IDS:-}"
db_instance_class="${DB_INSTANCE_CLASS:-db.t4g.micro}"
db_port="${DB_PORT:-5432}"
publicly_accessible="${PUBLICLY_ACCESSIBLE:-false}"
allow_existing_readonly="${ALLOW_EXISTING_TARGET_READONLY:-false}"

if [ "$confirm" != "I_APPROVE_REGION_LOCAL_DB_RESTORE" ]; then
  echo "Refusing region-local DB restore. Set CONFIRM_REGION_LOCAL_DB_RESTORE=I_APPROVE_REGION_LOCAL_DB_RESTORE after approval." >&2
  exit 2
fi

case "$target_standby" in
  mumbai|capetown) ;;
  *)
    echo "TARGET_STANDBY must be mumbai or capetown." >&2
    exit 2
    ;;
esac

case "$target_standby:$target_region" in
  mumbai:ap-south-1|capetown:af-south-1) ;;
  mumbai:|"capetown:") ;;
  *)
    echo "TARGET_REGION must be ap-south-1 for mumbai or af-south-1 for capetown." >&2
    exit 2
    ;;
esac

missing=0
[ -n "$target_region" ] || { print_missing TARGET_REGION; missing=1; }
[ -n "$snapshot_identifier" ] || { print_missing SNAPSHOT_IDENTIFIER; missing=1; }
[ -n "$target_db" ] || { print_missing TARGET_DB_IDENTIFIER; missing=1; }
[ -n "$db_subnet_group_name" ] || { print_missing DB_SUBNET_GROUP_NAME; missing=1; }
[ -n "$db_vpc_security_group_ids" ] || { print_missing DB_VPC_SECURITY_GROUP_IDS; missing=1; }
[ "$missing" -eq 0 ] || exit 2

target_db_lc="$(printf '%s' "$target_db" | /usr/bin/tr '[:upper:]' '[:lower:]')"
if [ "$target_db_lc" = "mscqr-prod-db" ]; then
  echo "Refusing to restore over production DB identifier: $target_db" >&2
  exit 2
fi
case "$target_db_lc" in
  *dr*|*restore*|*test*|*recovery*) ;;
  *)
    echo "TARGET_DB_IDENTIFIER must include dr, restore, test, or recovery." >&2
    exit 2
    ;;
esac

case "$publicly_accessible" in
  true|false) ;;
  *)
    echo "PUBLICLY_ACCESSIBLE must be true or false." >&2
    exit 2
    ;;
esac

security_group_args=""
normalized_security_groups="$(printf '%s' "$db_vpc_security_group_ids" | /usr/bin/tr ',' ' ')"
for sg_id in $normalized_security_groups; do
  case "$sg_id" in
    sg-*) security_group_args="$security_group_args $sg_id" ;;
    *)
      echo "Invalid security group id format: $sg_id" >&2
      exit 2
      ;;
  esac
done

create_artifact_dir
log_file="$DR_ARTIFACT_DIR/region-local-db-restore-approved.log"

run_restore() {
  echo "Timestamp: $DR_TIMESTAMP"
  echo "Target standby: $target_standby"
  echo "Target region: $target_region"
  echo "Snapshot identifier: $snapshot_identifier"
  echo "Target DB: $target_db"
  echo "DB subnet group: $db_subnet_group_name"
  echo "VPC security group IDs provided: yes"
  echo "DB instance class: $db_instance_class"
  echo "DB port: $db_port"
  echo "Publicly accessible: $publicly_accessible"
  echo
  echo "=== verifying target DB does not already exist ==="
  if aws rds describe-db-instances --region "$target_region" --db-instance-identifier "$target_db" > "$DR_ARTIFACT_DIR/existing-target-db.json" 2> "$DR_ARTIFACT_DIR/existing-target-db.err"; then
    echo "Target DB already exists: $target_db"
    if [ "$allow_existing_readonly" = "true" ]; then
      echo "ALLOW_EXISTING_TARGET_READONLY=true; described existing DB only and did not restore."
      return 0
    fi
    echo "Refusing to overwrite existing DB."
    return 2
  fi
  /bin/rm -f "$DR_ARTIFACT_DIR/existing-target-db.json" "$DR_ARTIFACT_DIR/existing-target-db.err"

  echo "=== restoring region-local DB instance from snapshot ==="
  set -- aws rds restore-db-instance-from-db-snapshot \
    --region "$target_region" \
    --db-instance-identifier "$target_db" \
    --db-snapshot-identifier "$snapshot_identifier" \
    --db-subnet-group-name "$db_subnet_group_name" \
    --vpc-security-group-ids $security_group_args \
    --db-instance-class "$db_instance_class" \
    --port "$db_port" \
    --tags Key=Project,Value=MSCQR Key=Purpose,Value=DR Key=TargetStandby,Value="$target_standby" Key=CreatedBy,Value=GitHubActionsOrOperator
  if [ "$publicly_accessible" = "true" ]; then
    set -- "$@" --publicly-accessible
  else
    set -- "$@" --no-publicly-accessible
  fi
  "$@"
  echo
  echo "Monitor command:"
  echo "aws rds describe-db-instances --region '$target_region' --db-instance-identifier '$target_db'"
}

set +e
run_restore > "$log_file" 2>&1
status="$?"
set -e

/bin/cat "$log_file"
exit "$status"
