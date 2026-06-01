#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=scripts/dr/common.sh
. "$SCRIPT_DIR/common.sh"

require_repo_root
require_command aws
require_command node

TARGET_REGION_GROUP="${TARGET_REGION_GROUP:-${1:-}}"
AWS_REGION="${AWS_REGION:-}"
ALB_ARN="${ALB_ARN:-}"
TARGET_GROUP_ARN="${TARGET_GROUP_ARN:-}"
ALB_ACCESS_LOGS_BUCKET="${ALB_ACCESS_LOGS_BUCKET:-${ACCESS_LOGS_BUCKET:-}}"
ALB_ACCESS_LOGS_PREFIX="${ALB_ACCESS_LOGS_PREFIX:-${ACCESS_LOGS_PREFIX:-}}"
WAF_WEB_ACL_NAME="${WAF_WEB_ACL_NAME:-${WAF_NAME:-mscqr-$TARGET_REGION_GROUP-regional-waf}}"
ASG_NAME="${ASG_NAME:-mscqr-$TARGET_REGION_GROUP-dr-asg}"
CHECK_PRODUCTION_DNS="${CHECK_PRODUCTION_DNS:-true}"
EXPECTED_PRODUCTION_DNS_VALUE="${EXPECTED_PRODUCTION_DNS_VALUE:-}"

case "$TARGET_REGION_GROUP" in
  mumbai|capetown) ;;
  *) echo "TARGET_REGION_GROUP must be mumbai or capetown." >&2; exit 2 ;;
esac

case "$TARGET_REGION_GROUP:$AWS_REGION" in
  mumbai:ap-south-1|capetown:af-south-1) ;;
  *) echo "AWS_REGION does not match TARGET_REGION_GROUP." >&2; exit 2 ;;
esac

if [ -z "$ALB_ARN" ] || [ -z "$TARGET_GROUP_ARN" ]; then
  echo "ALB_ARN and TARGET_GROUP_ARN are required." >&2
  exit 2
fi

create_artifact_dir
out_dir="$DR_ARTIFACT_DIR/hardening-state/$TARGET_REGION_GROUP"
/bin/mkdir -p "$out_dir"

prefix="MSCQR-$TARGET_REGION_GROUP"
aws cloudwatch describe-alarms \
  --region "$AWS_REGION" \
  --alarm-name-prefix "$prefix" \
  --output json > "$out_dir/cloudwatch-alarms.json"

aws elbv2 describe-load-balancer-attributes \
  --region "$AWS_REGION" \
  --load-balancer-arn "$ALB_ARN" \
  --output json > "$out_dir/alb-attributes.json"

aws elbv2 describe-target-health \
  --region "$AWS_REGION" \
  --target-group-arn "$TARGET_GROUP_ARN" \
  --output json > "$out_dir/target-health.json"

aws wafv2 get-web-acl-for-resource \
  --region "$AWS_REGION" \
  --resource-arn "$ALB_ARN" \
  --output json > "$out_dir/waf-association.json" 2>"$out_dir/waf-association.err" || true

aws autoscaling describe-auto-scaling-groups \
  --region "$AWS_REGION" \
  --auto-scaling-group-names "$ASG_NAME" \
  --output json > "$out_dir/asg.json" 2>"$out_dir/asg.err" || true

dns_status="not-checked"
if [ "$CHECK_PRODUCTION_DNS" = "true" ] && command -v dig >/dev/null 2>&1; then
  dig +short mscqr.com > "$out_dir/mscqr-apex-dns.txt"
  dig +short www.mscqr.com > "$out_dir/mscqr-www-dns.txt"
  dns_status="observed"
  if [ -n "$EXPECTED_PRODUCTION_DNS_VALUE" ]; then
    if /usr/bin/grep -qx "$EXPECTED_PRODUCTION_DNS_VALUE" "$out_dir/mscqr-apex-dns.txt" || /usr/bin/grep -qx "$EXPECTED_PRODUCTION_DNS_VALUE" "$out_dir/mscqr-www-dns.txt"; then
      dns_status="expected"
    else
      dns_status="unexpected"
    fi
  fi
fi

alarm_count="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); console.log((p.MetricAlarms || []).length)' "$out_dir/cloudwatch-alarms.json")"
healthy_count="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); console.log((p.TargetHealthDescriptions || []).filter((d) => d.TargetHealth && d.TargetHealth.State === "healthy").length)' "$out_dir/target-health.json")"
access_logs_enabled="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); const attrs=Object.fromEntries((p.Attributes || []).map(a=>[a.Key,a.Value])); console.log(attrs["access_logs.s3.enabled"] || "false")' "$out_dir/alb-attributes.json")"

{
  printf '# DR Hardening State Summary\n\n'
  printf '%s\n' "- Target region group: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- AWS region: \`$AWS_REGION\`"
  printf '%s\n' "- CloudWatch alarm count with prefix \`$prefix\`: \`$alarm_count\`"
  printf '%s\n' "- ALB access logs enabled: \`$access_logs_enabled\`"
  printf '%s\n' "- Expected access log bucket: \`${ALB_ACCESS_LOGS_BUCKET:-not-provided}\`"
  printf '%s\n' "- Expected access log prefix: \`${ALB_ACCESS_LOGS_PREFIX:-not-provided}\`"
  printf '%s\n' "- Healthy target count: \`$healthy_count\`"
  printf '%s\n' "- WAF association evidence: \`$out_dir/waf-association.json\`"
  printf '%s\n' "- ASG evidence: \`$out_dir/asg.json\`"
  printf '%s\n' "- Production DNS status: \`$dns_status\`"
} > "$out_dir/hardening-state-summary.md"

/bin/cat "$out_dir/hardening-state-summary.md"

if [ "$dns_status" = "unexpected" ]; then
  echo "Production DNS does not include EXPECTED_PRODUCTION_DNS_VALUE." >&2
  exit 3
fi
