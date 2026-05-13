#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=scripts/dr/common.sh
. "$SCRIPT_DIR/common.sh"

require_repo_root

TARGET_REGION_GROUP="${TARGET_REGION_GROUP:-${1:-}}"
HOSTED_ZONE_ID="${HOSTED_ZONE_ID:-Z0569586VLFIGGVI7HAZ}"
DOMAIN_NAME="${DOMAIN_NAME:-mscqr.com}"
WWW_DOMAIN_NAME="${WWW_DOMAIN_NAME:-www.mscqr.com}"
ALB_DNS_NAME="${ALB_DNS_NAME:-}"
ALB_HOSTED_ZONE_ID="${ALB_HOSTED_ZONE_ID:-}"
ROLLBACK_ALB_DNS_NAME="${ROLLBACK_ALB_DNS_NAME:-}"
ROLLBACK_ALB_HOSTED_ZONE_ID="${ROLLBACK_ALB_HOSTED_ZONE_ID:-}"
ROLLBACK_IP="${ROLLBACK_IP:-13.135.108.69}"

case "$TARGET_REGION_GROUP" in
  london|mumbai|capetown) ;;
  *)
    echo "TARGET_REGION_GROUP must be one of: london, mumbai, capetown." >&2
    exit 2
    ;;
esac

if [ -z "$ALB_DNS_NAME" ] || [ -z "$ALB_HOSTED_ZONE_ID" ]; then
  echo "ALB_DNS_NAME and ALB_HOSTED_ZONE_ID are required." >&2
  exit 2
fi

create_artifact_dir
plan_dir="$DR_ARTIFACT_DIR/route53-alb-cutover/$TARGET_REGION_GROUP"
/bin/mkdir -p "$plan_dir"

cutover_file="$plan_dir/cutover-to-$TARGET_REGION_GROUP-alb.json"
rollback_file="$plan_dir/rollback-from-$TARGET_REGION_GROUP-alb.json"
summary_file="$plan_dir/summary.md"

/bin/cat > "$cutover_file" <<JSON
{
  "Comment": "MSCQR approved DNS cutover to $TARGET_REGION_GROUP regional ALB",
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$DOMAIN_NAME.",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "$ALB_HOSTED_ZONE_ID",
          "DNSName": "$ALB_DNS_NAME",
          "EvaluateTargetHealth": true
        }
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$WWW_DOMAIN_NAME.",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [
          { "Value": "$DOMAIN_NAME" }
        ]
      }
    }
  ]
}
JSON

if [ -n "$ROLLBACK_ALB_DNS_NAME" ] && [ -n "$ROLLBACK_ALB_HOSTED_ZONE_ID" ]; then
  /bin/cat > "$rollback_file" <<JSON
{
  "Comment": "MSCQR approved DNS rollback to previous ALB",
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$DOMAIN_NAME.",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "$ROLLBACK_ALB_HOSTED_ZONE_ID",
          "DNSName": "$ROLLBACK_ALB_DNS_NAME",
          "EvaluateTargetHealth": true
        }
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$WWW_DOMAIN_NAME.",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [
          { "Value": "$DOMAIN_NAME" }
        ]
      }
    }
  ]
}
JSON
else
  /bin/cat > "$rollback_file" <<JSON
{
  "Comment": "MSCQR approved DNS rollback to prior London EC2 A record",
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$DOMAIN_NAME.",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [
          { "Value": "$ROLLBACK_IP" }
        ]
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$WWW_DOMAIN_NAME.",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [
          { "Value": "$DOMAIN_NAME" }
        ]
      }
    }
  ]
}
JSON
fi

{
  printf '# Route 53 ALB cutover plan\n\n'
  printf '%s\n' "- Hosted zone: \`$HOSTED_ZONE_ID\`"
  printf '%s\n' "- Cutover target: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- ALB DNS name: \`$ALB_DNS_NAME\`"
  printf '%s\n' "- ALB hosted zone ID: \`$ALB_HOSTED_ZONE_ID\`"
  printf '%s\n' "- Cutover JSON: \`$cutover_file\`"
  printf '%s\n\n' "- Rollback JSON: \`$rollback_file\`"
  printf 'This generator does not apply DNS. Use the approved DNS apply workflow only after incident commander approval.\n'
} > "$summary_file"

/bin/cat "$summary_file"
