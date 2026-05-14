#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=scripts/dr/common.sh
. "$SCRIPT_DIR/common.sh"

require_repo_root

TARGET_REGION_GROUP="${TARGET_REGION_GROUP:-${1:-}}"
HOSTED_ZONE_ID="${HOSTED_ZONE_ID:-Z0569586VLFIGGVI7HAZ}"
DOMAIN_NAME="${DOMAIN_NAME:-mscqr.com}"
ALB_DNS_NAME="${ALB_DNS_NAME:-}"
ALB_HOSTED_ZONE_ID="${ALB_HOSTED_ZONE_ID:-}"

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
plan_dir="$DR_ARTIFACT_DIR/route53-regional-test-records/$TARGET_REGION_GROUP"
/bin/mkdir -p "$plan_dir"

record_name="dr-$TARGET_REGION_GROUP.$DOMAIN_NAME"
change_file="$plan_dir/$record_name-change-batch.json"
summary_file="$plan_dir/summary.md"

/bin/cat > "$change_file" <<JSON
{
  "Comment": "MSCQR regional ALB test record for $TARGET_REGION_GROUP",
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$record_name.",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "$ALB_HOSTED_ZONE_ID",
          "DNSName": "$ALB_DNS_NAME",
          "EvaluateTargetHealth": true
        }
      }
    }
  ]
}
JSON

{
  printf '# Regional ALB test record plan\n\n'
  printf '%s\n' "- Hosted zone: \`$HOSTED_ZONE_ID\`"
  printf '%s\n' "- Test record: \`$record_name\`"
  printf '%s\n' "- ALB DNS name: \`$ALB_DNS_NAME\`"
  printf '%s\n' "- ALB hosted zone ID: \`$ALB_HOSTED_ZONE_ID\`"
  printf '%s\n\n' "- Change batch: \`$change_file\`"
  printf 'This generator does not apply DNS. Use the approved DNS apply workflow to create the test record.\n'
} > "$summary_file"

/bin/cat "$summary_file"
