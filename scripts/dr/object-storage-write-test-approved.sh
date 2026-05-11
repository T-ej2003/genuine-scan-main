#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root

confirm="${CONFIRM_OBJECT_WRITE_TEST:-}"
delete_confirm="${CONFIRM_DELETE_TEST_OBJECT:-}"
bucket="${BUCKET:-${1:-}}"

if [ "$confirm" != "I_APPROVE_OBJECT_STORAGE_WRITE_TEST" ]; then
  echo "Refusing object storage write test. Set CONFIRM_OBJECT_WRITE_TEST=I_APPROVE_OBJECT_STORAGE_WRITE_TEST after approval." >&2
  exit 2
fi

[ -n "$bucket" ] || { print_missing BUCKET; exit 2; }
require_command aws
create_artifact_dir
log_file="$DR_ARTIFACT_DIR/object-storage-write-test.log"
test_file="$DR_ARTIFACT_DIR/healthcheck.txt"
test_key="dr-tests/$DR_TIMESTAMP/healthcheck.txt"

printf 'MSCQR DR object storage write test %s\n' "$DR_TIMESTAMP" > "$test_file"

set +e
{
  echo "Timestamp: $DR_TIMESTAMP"
  echo "Bucket: $bucket"
  echo "Test object: $test_key"
  echo
  echo "=== writing approved test object ==="
  aws s3 cp "$test_file" "s3://$bucket/$test_key" --content-type text/plain
  echo
  echo "=== verifying approved test object ==="
  aws s3api head-object --bucket "$bucket" --key "$test_key"
  if [ "$delete_confirm" = "I_APPROVE_DELETE_DR_TEST_OBJECT" ]; then
    echo
    echo "=== deleting only the approved DR test object ==="
    aws s3 rm "s3://$bucket/$test_key"
  else
    echo
    echo "Leaving test object in place. Set CONFIRM_DELETE_TEST_OBJECT=I_APPROVE_DELETE_DR_TEST_OBJECT to delete only $test_key."
  fi
} > "$log_file" 2>&1
status="$?"
set -e

/bin/cat "$log_file"
exit "$status"
