#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root
require_command aws

target_standby="${TARGET_STANDBY:-}"
target_region="${TARGET_REGION:-}"
target_db="${TARGET_DB_IDENTIFIER:-}"
db_subnet_group_name="${DB_SUBNET_GROUP_NAME:-}"
db_vpc_security_group_ids="${DB_VPC_SECURITY_GROUP_IDS:-}"

case "$target_standby" in
  mumbai|capetown|"") ;;
  *)
    echo "TARGET_STANDBY must be mumbai or capetown when provided." >&2
    exit 2
    ;;
esac

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
[ -n "$target_db" ] || { print_missing TARGET_DB_IDENTIFIER; missing=1; }
[ "$missing" -eq 0 ] || exit 2

create_artifact_dir
log_file="$DR_ARTIFACT_DIR/target-region-db-readiness.log"
db_file="$DR_ARTIFACT_DIR/target-db-instance.json"

set +e
{
  echo "Timestamp: $DR_TIMESTAMP"
  echo "Target standby: ${target_standby:-not provided}"
  echo "Target region: $target_region"
  echo "Target DB: $target_db"
  echo
  echo "=== describe target DB ==="
  aws rds describe-db-instances --region "$target_region" --db-instance-identifier "$target_db" > "$db_file"
  /bin/cat "$db_file"
  echo
  status="$(aws rds describe-db-instances --region "$target_region" --db-instance-identifier "$target_db" --query 'DBInstances[0].DBInstanceStatus' --output text)"
  endpoint="$(aws rds describe-db-instances --region "$target_region" --db-instance-identifier "$target_db" --query 'DBInstances[0].Endpoint.Address' --output text)"
  port="$(aws rds describe-db-instances --region "$target_region" --db-instance-identifier "$target_db" --query 'DBInstances[0].Endpoint.Port' --output text)"
  subnet_group="$(aws rds describe-db-instances --region "$target_region" --db-instance-identifier "$target_db" --query 'DBInstances[0].DBSubnetGroup.DBSubnetGroupName' --output text)"
  sg_ids="$(aws rds describe-db-instances --region "$target_region" --db-instance-identifier "$target_db" --query 'DBInstances[0].VpcSecurityGroups[].VpcSecurityGroupId' --output text)"
  echo "Status: $status"
  echo "Endpoint: $endpoint"
  echo "Port: $port"
  echo "DB subnet group: $subnet_group"
  echo "VPC security groups: $sg_ids"
  if [ -n "$db_subnet_group_name" ] && [ "$db_subnet_group_name" != "$subnet_group" ]; then
    echo "WARNING: Expected subnet group $db_subnet_group_name but found $subnet_group"
  fi
  if [ -n "$db_vpc_security_group_ids" ]; then
    echo "Expected VPC security groups: $db_vpc_security_group_ids"
  fi
} > "$log_file" 2>&1
status_code="$?"
set -e

/bin/cat "$log_file"
exit "$status_code"
