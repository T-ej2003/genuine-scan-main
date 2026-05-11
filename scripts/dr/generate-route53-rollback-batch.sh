#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

usage() {
  echo "Usage: HOSTNAME=www.mscqr.com ROLLBACK_VALUE=old.example.com TTL=60 $0"
  echo "Flags: --hostname value --rollback-value value --ttl seconds --record-type CNAME|A"
}

require_repo_root

hostname="${HOSTNAME:-}"
rollback_value="${ROLLBACK_VALUE:-}"
ttl="${TTL:-}"
record_type="${RECORD_TYPE:-CNAME}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --hostname) hostname="${2:-}"; shift 2 ;;
    --rollback-value) rollback_value="${2:-}"; shift 2 ;;
    --ttl) ttl="${2:-}"; shift 2 ;;
    --record-type) record_type="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

missing=0
[ -n "$hostname" ] || { print_missing HOSTNAME; missing=1; }
[ -n "$rollback_value" ] || { print_missing ROLLBACK_VALUE; missing=1; }
[ -n "$ttl" ] || { print_missing TTL; missing=1; }
[ "$missing" -eq 0 ] || exit 2

case "$ttl" in
  *[!0-9]*|'') echo "TTL must be a positive integer." >&2; exit 2 ;;
esac

case "$record_type" in
  A|AAAA|CNAME) ;;
  *) echo "RECORD_TYPE must be A, AAAA, or CNAME for this generator." >&2; exit 2 ;;
esac

create_artifact_dir
output_file="$DR_ARTIFACT_DIR/route53-rollback-batch.json"
hostname_json="$(json_escape "$hostname")"
rollback_json="$(json_escape "$rollback_value")"

{
  printf '{\n'
  printf '  "Comment": "MSCQR manual DR DNS rollback candidate generated %s; review before apply",\n' "$DR_TIMESTAMP"
  printf '  "Changes": [\n'
  printf '    {\n'
  printf '      "Action": "UPSERT",\n'
  printf '      "ResourceRecordSet": {\n'
  printf '        "Name": "%s",\n' "$hostname_json"
  printf '        "Type": "%s",\n' "$record_type"
  printf '        "TTL": %s,\n' "$ttl"
  printf '        "ResourceRecords": [\n'
  printf '          { "Value": "%s" }\n' "$rollback_json"
  printf '        ]\n'
  printf '      }\n'
  printf '    }\n'
  printf '  ]\n'
  printf '}\n'
} > "$output_file"

echo "Generated $output_file"
echo "# Manual rollback command after incident commander approval:"
echo "# HOSTED_ZONE_ID=Zxxxxxxxx ROLLBACK_BATCH_FILE=$output_file CONFIRM_DNS_ROLLBACK=I_APPROVE_MANUAL_DNS_ROLLBACK scripts/dr/apply-route53-rollback.sh"
