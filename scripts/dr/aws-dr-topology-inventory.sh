#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

infer_target_region() {
  case "$1" in
    mumbai) echo "ap-south-1" ;;
    capetown) echo "af-south-1" ;;
    "") echo "" ;;
    *)
      echo "Unsupported TARGET_STANDBY: $1" >&2
      echo "Allowed standby targets: mumbai, capetown" >&2
      exit 2
      ;;
  esac
}

require_repo_root
require_command aws

source_region="${SOURCE_REGION:-eu-west-2}"
target_standby="${TARGET_STANDBY:-}"
target_region="${TARGET_REGION:-}"
source_db="${SOURCE_DB_IDENTIFIER:-mscqr-prod-db}"

if [ -z "$target_region" ]; then
  target_region="$(infer_target_region "$target_standby")"
fi

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
[ -n "$source_region" ] || { print_missing SOURCE_REGION; missing=1; }
[ -n "$target_region" ] || { print_missing TARGET_REGION; missing=1; }
[ -n "$source_db" ] || { print_missing SOURCE_DB_IDENTIFIER; missing=1; }
[ "$missing" -eq 0 ] || exit 2

create_artifact_dir
topology_dir="$DR_ARTIFACT_DIR/topology"
/bin/mkdir -p "$topology_dir"
summary_file="$DR_ARTIFACT_DIR/topology-summary.md"

run_json() {
  description="$1"
  output_file="$2"
  shift 2
  echo "Collecting $description -> $output_file"
  if "$@" > "$output_file" 2> "$output_file.err"; then
    /bin/rm -f "$output_file.err"
    return 0
  fi
  echo "Failed to collect $description. See $output_file.err." >&2
  return 1
}

source_db_file="$topology_dir/source-db-instance.json"
source_snapshots_file="$topology_dir/source-db-snapshots.json"
latest_snapshot_file="$topology_dir/latest-automated-snapshot.json"
source_subnet_groups_file="$topology_dir/source-db-subnet-groups.json"
target_subnet_groups_file="$topology_dir/target-db-subnet-groups.json"
source_vpcs_file="$topology_dir/source-vpcs.json"
source_subnets_file="$topology_dir/source-subnets.json"
source_security_groups_file="$topology_dir/source-security-groups.json"
target_vpcs_file="$topology_dir/target-vpcs.json"
target_subnets_file="$topology_dir/target-subnets.json"
target_security_groups_file="$topology_dir/target-security-groups.json"
source_kms_file="$topology_dir/source-kms-key.json"

run_json "source DB instance" "$source_db_file" \
  aws rds describe-db-instances --region "$source_region" --db-instance-identifier "$source_db"
run_json "source automated DB snapshots" "$source_snapshots_file" \
  aws rds describe-db-snapshots --region "$source_region" --db-instance-identifier "$source_db" --snapshot-type automated --max-items 50
run_json "latest automated source snapshot" "$latest_snapshot_file" \
  aws rds describe-db-snapshots --region "$source_region" --db-instance-identifier "$source_db" --snapshot-type automated --query 'reverse(sort_by(DBSnapshots,&SnapshotCreateTime))[0]' --output json
run_json "source DB subnet groups" "$source_subnet_groups_file" \
  aws rds describe-db-subnet-groups --region "$source_region"
run_json "target DB subnet groups" "$target_subnet_groups_file" \
  aws rds describe-db-subnet-groups --region "$target_region"
run_json "source VPCs" "$source_vpcs_file" \
  aws ec2 describe-vpcs --region "$source_region"
run_json "source subnets" "$source_subnets_file" \
  aws ec2 describe-subnets --region "$source_region"
run_json "source security groups" "$source_security_groups_file" \
  aws ec2 describe-security-groups --region "$source_region"
run_json "target VPCs" "$target_vpcs_file" \
  aws ec2 describe-vpcs --region "$target_region"
run_json "target subnets" "$target_subnets_file" \
  aws ec2 describe-subnets --region "$target_region"
run_json "target security groups" "$target_security_groups_file" \
  aws ec2 describe-security-groups --region "$target_region"

latest_restorable_time="$(aws rds describe-db-instances --region "$source_region" --db-instance-identifier "$source_db" --query 'DBInstances[0].LatestRestorableTime' --output text 2>/dev/null || true)"
source_vpc_id="$(aws rds describe-db-instances --region "$source_region" --db-instance-identifier "$source_db" --query 'DBInstances[0].DBSubnetGroup.VpcId' --output text 2>/dev/null || true)"
source_sg_ids="$(aws rds describe-db-instances --region "$source_region" --db-instance-identifier "$source_db" --query 'DBInstances[0].VpcSecurityGroups[].VpcSecurityGroupId' --output text 2>/dev/null || true)"
kms_key_id="$(aws rds describe-db-instances --region "$source_region" --db-instance-identifier "$source_db" --query 'DBInstances[0].KmsKeyId' --output text 2>/dev/null || true)"
latest_snapshot_id="$(aws rds describe-db-snapshots --region "$source_region" --db-instance-identifier "$source_db" --snapshot-type automated --query 'reverse(sort_by(DBSnapshots,&SnapshotCreateTime))[0].DBSnapshotIdentifier' --output text 2>/dev/null || true)"
latest_snapshot_time="$(aws rds describe-db-snapshots --region "$source_region" --db-instance-identifier "$source_db" --snapshot-type automated --query 'reverse(sort_by(DBSnapshots,&SnapshotCreateTime))[0].SnapshotCreateTime' --output text 2>/dev/null || true)"
target_subnet_group_count="$(aws rds describe-db-subnet-groups --region "$target_region" --query 'length(DBSubnetGroups)' --output text 2>/dev/null || echo 0)"
target_sg_count="$(aws ec2 describe-security-groups --region "$target_region" --query 'length(SecurityGroups)' --output text 2>/dev/null || echo 0)"

if [ -n "$kms_key_id" ] && [ "$kms_key_id" != "None" ]; then
  if ! run_json "source KMS key" "$source_kms_file" aws kms describe-key --region "$source_region" --key-id "$kms_key_id"; then
    echo "KMS key was detected but could not be described: $kms_key_id" > "$source_kms_file.note"
  fi
fi

{
  echo "# AWS DR Topology Inventory"
  echo
  echo "Generated: $DR_TIMESTAMP"
  echo
  echo "## Inputs"
  echo
  echo "- Source region: $source_region"
  echo "- Target standby: ${target_standby:-not provided}"
  echo "- Target region: $target_region"
  echo "- Source DB identifier: $source_db"
  echo
  echo "## Source DB"
  echo
  echo "- Latest restorable time: ${latest_restorable_time:-unknown}"
  echo "- Latest automated snapshot: ${latest_snapshot_id:-unknown}"
  echo "- Latest automated snapshot time: ${latest_snapshot_time:-unknown}"
  echo "- Source VPC: ${source_vpc_id:-unknown}"
  echo "- Source security groups: ${source_sg_ids:-unknown}"
  echo "- Source KMS key: ${kms_key_id:-not detected}"
  echo
  echo "## Target Region Candidates"
  echo
  echo "- Target DB subnet group count: ${target_subnet_group_count:-0}"
  echo "- Target security group count: ${target_sg_count:-0}"
  echo
  echo "## Gaps To Resolve"
  echo
  if [ "${target_subnet_group_count:-0}" = "0" ]; then
    echo "- Target region has no visible RDS DB subnet groups. Create or approve one before restore."
  else
    echo "- Confirm the selected target DB subnet group spans approved private subnets."
  fi
  if [ "${target_sg_count:-0}" = "0" ]; then
    echo "- Target region has no visible security groups. Create or approve one before restore."
  else
    echo "- Confirm the selected target security group permits the selected standby app to reach PostgreSQL."
  fi
  if [ -n "$kms_key_id" ] && [ "$kms_key_id" != "None" ]; then
    echo "- Confirm encrypted snapshot copy can use an approved target-region KMS key."
  fi
  echo
  echo "## Evidence Files"
  echo
  echo "JSON evidence was saved under \`$topology_dir\`."
} > "$summary_file"

/bin/cat "$summary_file"
