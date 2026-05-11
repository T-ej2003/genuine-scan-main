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
db_subnet_group_name="${DB_SUBNET_GROUP_NAME:-}"
db_vpc_security_group_ids="${DB_VPC_SECURITY_GROUP_IDS:-}"

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
  echo "- DB subnet group name: ${db_subnet_group_name:-not provided}"
  echo "- VPC security group IDs: ${db_vpc_security_group_ids:-not provided}"
  echo
  echo "## Operator Review Checklist"
  echo
  echo "- [ ] Incident commander approved recovery target creation."
  echo "- [ ] Recovery point satisfies the incident RPO."
  echo "- [ ] Target DB identifier is new and is not the production primary."
  echo "- [ ] Target region network, subnet group, and security groups are approved."
  echo "- [ ] DB subnet group is set when the target VPC has no default subnets."
  echo "- [ ] VPC security group IDs are approved for the recovery target."
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
    if [ -n "$db_subnet_group_name" ]; then
      echo "#   --db-subnet-group-name '$db_subnet_group_name' \\"
    fi
    if [ -n "$db_vpc_security_group_ids" ]; then
      echo "#   --vpc-security-group-ids $db_vpc_security_group_ids \\"
    fi
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
    if [ -n "$db_subnet_group_name" ]; then
      echo "#   --db-subnet-group-name '$db_subnet_group_name' \\"
    fi
    if [ -n "$db_vpc_security_group_ids" ]; then
      echo "#   --vpc-security-group-ids $db_vpc_security_group_ids \\"
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
  echo "## Network Notes"
  echo
  echo "The initial London restore drill failed with InvalidSubnet because no default subnet existed in the target VPC."
  echo "For London restore drills, set db_subnet_group_name to rds-ec2-db-subnet-group-1 unless a dedicated recovery subnet group is approved."
  echo "The current London drill security group observed during readiness was sg-07db1a9130c6df8d5. Re-validate this before production incident use."
  echo
  echo "## Non-Goals"
  echo
  echo "This plan does not modify primary production, delete databases, overwrite an existing DB, or perform failover."
} > "$output_file"

echo "Generated $output_file"
