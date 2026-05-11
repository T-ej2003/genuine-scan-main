#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root
require_command curl
create_artifact_dir
log_file="$DR_ARTIFACT_DIR/public-health.log"

echo "Checking public MSCQR health endpoints"
echo "Writing evidence to $log_file"

set +e
{
  echo "Timestamp: $DR_TIMESTAMP"
  for url in \
    "https://www.mscqr.com/healthz" \
    "https://www.mscqr.com/api/health/ready"
  do
    echo "=== $url ==="
    curl --fail --show-error --silent --location --max-time 20 \
      --output /dev/null \
      --write-out 'http_code=%{http_code} time_total=%{time_total}s\n' \
      "$url"
  done
} > "$log_file" 2>&1
status="$?"
set -e

/bin/cat "$log_file"
exit "$status"
