#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

usage() {
  echo "Usage: HOSTED_ZONE_ID=... CHANGE_BATCH_FILE=... CONFIRM_DNS_CUTOVER=I_APPROVE_MANUAL_DNS_CUTOVER $0"
}

require_repo_root

hosted_zone_id="${HOSTED_ZONE_ID:-}"
change_batch_file="${CHANGE_BATCH_FILE:-}"
confirm="${CONFIRM_DNS_CUTOVER:-}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --hosted-zone-id) hosted_zone_id="${2:-}"; shift 2 ;;
    --change-batch-file) change_batch_file="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$hosted_zone_id" ] || { print_missing HOSTED_ZONE_ID; exit 2; }
[ -n "$change_batch_file" ] || { print_missing CHANGE_BATCH_FILE; exit 2; }
[ -f "$change_batch_file" ] || { echo "Change batch file not found: $change_batch_file" >&2; exit 2; }

if [ "$confirm" != "I_APPROVE_MANUAL_DNS_CUTOVER" ]; then
  echo "Refusing DNS cutover. Set CONFIRM_DNS_CUTOVER=I_APPROVE_MANUAL_DNS_CUTOVER after explicit incident commander approval." >&2
  exit 2
fi

require_command aws
create_artifact_dir
log_file="$DR_ARTIFACT_DIR/route53-apply.log"

set +e
{
  echo "Timestamp: $DR_TIMESTAMP"
  echo "Hosted zone: $hosted_zone_id"
  echo "Change batch: $change_batch_file"
  echo
  echo "=== current DNS before change ==="
  if command -v dig >/dev/null 2>&1; then
    dig +short "${HOSTNAME:-www.mscqr.com}"
  elif command -v nslookup >/dev/null 2>&1; then
    nslookup "${HOSTNAME:-www.mscqr.com}"
  else
    echo "No local DNS inspection tool found; continuing because AWS apply was explicitly approved."
  fi
  echo
  echo "=== applying Route 53 change ==="
  change_id="$(aws route53 change-resource-record-sets \
    --hosted-zone-id "$hosted_zone_id" \
    --change-batch "file://$change_batch_file" \
    --query 'ChangeInfo.Id' \
    --output text)"
  echo "Route 53 change id: $change_id"
  if [ -n "$change_id" ]; then
    echo "=== waiting for Route 53 INSYNC ==="
    aws route53 wait resource-record-sets-changed --id "$change_id"
  fi
  echo
  echo "=== public health after change ==="
  scripts/dr/public-health.sh
} > "$log_file" 2>&1
status="$?"
set -e

/bin/cat "$log_file"
exit "$status"
