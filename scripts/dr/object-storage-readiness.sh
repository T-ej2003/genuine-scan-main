#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root
bucket="${BUCKET:-${1:-}}"
test_object_key="${TEST_OBJECT_KEY:-${2:-}}"
create_artifact_dir
log_file="$DR_ARTIFACT_DIR/object-storage-readiness.log"

set +e
{
  echo "Timestamp: $DR_TIMESTAMP"
  echo "Purpose: read-only object storage readiness inspection"
  if [ -z "$bucket" ]; then
    echo "Missing BUCKET. Example: BUCKET=mscqr-prod-assets scripts/dr/object-storage-readiness.sh"
    exit 2
  fi
  if ! command -v aws >/dev/null 2>&1; then
    echo "Missing aws CLI."
    exit 127
  fi

  echo "=== aws s3 ls s3://$bucket ==="
  aws s3 ls "s3://$bucket"

  if [ -n "$test_object_key" ]; then
    echo
    echo "=== aws s3api head-object s3://$bucket/$test_object_key ==="
    aws s3api head-object --bucket "$bucket" --key "$test_object_key"
  fi
} > "$log_file" 2>&1
status="$?"
set -e

/bin/cat "$log_file"
exit "$status"
