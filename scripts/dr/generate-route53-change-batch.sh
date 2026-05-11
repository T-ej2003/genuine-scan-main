#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

usage() {
  echo "Usage: HOSTNAME=www.mscqr.com TARGET_VALUE=target.example.com TTL=60 ACTION=UPSERT $0"
  echo "Flags: --hostname value --target-value value --ttl seconds --action UPSERT|CREATE --record-type CNAME|A"
}

require_repo_root

hostname="${HOSTNAME:-}"
target_value="${TARGET_VALUE:-}"
ttl="${TTL:-}"
action="${ACTION:-}"
record_type="${RECORD_TYPE:-CNAME}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --hostname) hostname="${2:-}"; shift 2 ;;
    --target-value) target_value="${2:-}"; shift 2 ;;
    --ttl) ttl="${2:-}"; shift 2 ;;
    --action) action="${2:-}"; shift 2 ;;
    --record-type) record_type="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

missing=0
[ -n "$hostname" ] || { print_missing HOSTNAME; missing=1; }
[ -n "$target_value" ] || { print_missing TARGET_VALUE; missing=1; }
[ -n "$ttl" ] || { print_missing TTL; missing=1; }
[ -n "$action" ] || { print_missing ACTION; missing=1; }
[ "$missing" -eq 0 ] || exit 2

case "$action" in
  UPSERT|CREATE) ;;
  *) echo "ACTION must be UPSERT or CREATE." >&2; exit 2 ;;
esac

case "$ttl" in
  *[!0-9]*|'') echo "TTL must be a positive integer." >&2; exit 2 ;;
esac

case "$record_type" in
  A|AAAA|CNAME) ;;
  *) echo "RECORD_TYPE must be A, AAAA, or CNAME for this generator." >&2; exit 2 ;;
esac

create_artifact_dir
output_file="$DR_ARTIFACT_DIR/route53-change-batch.json"
hostname_json="$(json_escape "$hostname")"
target_json="$(json_escape "$target_value")"

{
  printf '{\n'
  printf '  "Comment": "MSCQR manual DR DNS cutover candidate generated %s; review before apply",\n' "$DR_TIMESTAMP"
  printf '  "Changes": [\n'
  printf '    {\n'
  printf '      "Action": "%s",\n' "$action"
  printf '      "ResourceRecordSet": {\n'
  printf '        "Name": "%s",\n' "$hostname_json"
  printf '        "Type": "%s",\n' "$record_type"
  printf '        "TTL": %s,\n' "$ttl"
  printf '        "ResourceRecords": [\n'
  printf '          { "Value": "%s" }\n' "$target_json"
  printf '        ]\n'
  printf '      }\n'
  printf '    }\n'
  printf '  ]\n'
  printf '}\n'
} > "$output_file"

echo "Generated $output_file"
echo "# Manual apply command after incident commander approval:"
echo "# HOSTED_ZONE_ID=Zxxxxxxxx CONFIRM_DNS_CUTOVER=I_APPROVE_MANUAL_DNS_CUTOVER scripts/dr/apply-route53-change.sh --change-batch-file $output_file"
