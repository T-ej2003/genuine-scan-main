#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root
create_artifact_dir
log_file="$DR_ARTIFACT_DIR/db-readiness.log"

aws_region="${AWS_REGION:-}"
db_identifier="${DB_IDENTIFIER:-}"
db_cluster_identifier="${DB_CLUSTER_IDENTIFIER:-}"

set +e
{
  echo "Timestamp: $DR_TIMESTAMP"
  echo "Purpose: read-only RDS recovery readiness inspection"
  missing=0
  [ -n "$aws_region" ] || { echo "Missing AWS_REGION."; missing=1; }
  if [ -z "$db_identifier" ] && [ -z "$db_cluster_identifier" ]; then
    echo "Missing DB_IDENTIFIER or DB_CLUSTER_IDENTIFIER."
    missing=1
  fi
  if ! command -v aws >/dev/null 2>&1; then
    echo "Missing aws CLI."
    missing=1
  fi
  if [ "$missing" -ne 0 ]; then
    echo
    echo "Example:"
    echo "AWS_PROFILE=dr-operator AWS_REGION=eu-west-2 DB_IDENTIFIER=mscqr-prod scripts/dr/db-readiness.sh"
    exit 2
  fi

  echo "AWS_PROFILE: ${AWS_PROFILE:-default/ambient credentials}"
  echo "AWS_REGION: $aws_region"
  echo

  if [ -n "$db_identifier" ]; then
    echo "=== describe-db-instances $db_identifier ==="
    aws rds describe-db-instances --region "$aws_region" --db-instance-identifier "$db_identifier"
    echo
    echo "=== describe-db-snapshots $db_identifier ==="
    aws rds describe-db-snapshots --region "$aws_region" --db-instance-identifier "$db_identifier"
  fi

  if [ -n "$db_cluster_identifier" ]; then
    echo
    echo "=== describe-db-clusters $db_cluster_identifier ==="
    aws rds describe-db-clusters --region "$aws_region" --db-cluster-identifier "$db_cluster_identifier"
    echo
    echo "=== describe-db-cluster-snapshots $db_cluster_identifier ==="
    aws rds describe-db-cluster-snapshots --region "$aws_region" --db-cluster-identifier "$db_cluster_identifier"
  fi
} > "$log_file" 2>&1
status="$?"
set -e

/bin/cat "$log_file"
exit "$status"
