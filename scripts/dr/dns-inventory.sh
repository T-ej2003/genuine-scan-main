#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root
hostname="${1:-${HOSTNAME:-www.mscqr.com}}"
create_artifact_dir
log_file="$DR_ARTIFACT_DIR/dns-inventory.log"

echo "Capturing read-only DNS inventory for $hostname"
echo "Writing evidence to $log_file"

set +e
{
  echo "Timestamp: $DR_TIMESTAMP"
  echo "Hostname: $hostname"
  echo
  if command -v dig >/dev/null 2>&1; then
    echo "=== dig +short $hostname ==="
    dig +short "$hostname"
    echo
    echo "=== dig +trace $hostname ==="
    dig +trace "$hostname"
  elif command -v nslookup >/dev/null 2>&1; then
    echo "=== nslookup $hostname ==="
    nslookup "$hostname"
  else
    echo "Neither dig nor nslookup is available."
    exit 127
  fi
} > "$log_file" 2>&1
status="$?"
set -e

/bin/cat "$log_file"
exit "$status"
