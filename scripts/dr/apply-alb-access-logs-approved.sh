#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=scripts/dr/common.sh
. "$SCRIPT_DIR/common.sh"

require_repo_root
require_command aws

TARGET_REGION_GROUP="${TARGET_REGION_GROUP:-${1:-}}"
AWS_REGION="${AWS_REGION:-}"
ALB_ARN="${ALB_ARN:-}"
ALB_ACCESS_LOGS_BUCKET="${ALB_ACCESS_LOGS_BUCKET:-${ACCESS_LOGS_BUCKET:-}}"
ALB_ACCESS_LOGS_PREFIX="${ALB_ACCESS_LOGS_PREFIX:-${ACCESS_LOGS_PREFIX:-}}"
CONFIRM_ALB_ACCESS_LOGS_APPLY="${CONFIRM_ALB_ACCESS_LOGS_APPLY:-}"

case "$TARGET_REGION_GROUP" in
  mumbai|capetown) ;;
  *) echo "TARGET_REGION_GROUP must be mumbai or capetown." >&2; exit 2 ;;
esac

case "$TARGET_REGION_GROUP:$AWS_REGION" in
  mumbai:ap-south-1|capetown:af-south-1) ;;
  *) echo "AWS_REGION does not match TARGET_REGION_GROUP." >&2; exit 2 ;;
esac

if [ "$CONFIRM_ALB_ACCESS_LOGS_APPLY" != "I_APPROVE_ALB_ACCESS_LOGS_APPLY" ]; then
  echo "Refusing ALB access log apply without CONFIRM_ALB_ACCESS_LOGS_APPLY=I_APPROVE_ALB_ACCESS_LOGS_APPLY." >&2
  exit 2
fi

if [ -z "$ALB_ARN" ] || [ -z "$ALB_ACCESS_LOGS_BUCKET" ] || [ -z "$ALB_ACCESS_LOGS_PREFIX" ]; then
  echo "ALB_ARN, ALB_ACCESS_LOGS_BUCKET, and ALB_ACCESS_LOGS_PREFIX are required." >&2
  exit 2
fi

case "$ALB_ACCESS_LOGS_BUCKET" in
  mscqr-prod-*artifacts*|*app*artifacts*|*application*artifacts*)
    echo "Refusing to use a production/application artifact bucket for ALB access logs: $ALB_ACCESS_LOGS_BUCKET" >&2
    exit 2
    ;;
esac

create_artifact_dir
out_dir="$DR_ARTIFACT_DIR/hardening-alb-access-logs/$TARGET_REGION_GROUP"
/bin/mkdir -p "$out_dir"

aws s3api head-bucket --bucket "$ALB_ACCESS_LOGS_BUCKET"
aws s3api get-bucket-location --bucket "$ALB_ACCESS_LOGS_BUCKET" --output json > "$out_dir/bucket-location.json" || true
aws s3api get-bucket-policy --bucket "$ALB_ACCESS_LOGS_BUCKET" --output json > "$out_dir/bucket-policy.json" 2>"$out_dir/bucket-policy.err" || true

aws elbv2 describe-load-balancer-attributes \
  --region "$AWS_REGION" \
  --load-balancer-arn "$ALB_ARN" \
  --output json > "$out_dir/before-attributes.json"

aws elbv2 modify-load-balancer-attributes \
  --region "$AWS_REGION" \
  --load-balancer-arn "$ALB_ARN" \
  --attributes \
    Key=access_logs.s3.enabled,Value=true \
    Key=access_logs.s3.bucket,Value="$ALB_ACCESS_LOGS_BUCKET" \
    Key=access_logs.s3.prefix,Value="$ALB_ACCESS_LOGS_PREFIX" \
  --output json > "$out_dir/modify-attributes.json"

aws elbv2 describe-load-balancer-attributes \
  --region "$AWS_REGION" \
  --load-balancer-arn "$ALB_ARN" \
  --output json > "$out_dir/after-attributes.json"

{
  printf '# ALB Access Logs Apply Evidence\n\n'
  printf '%s\n' "- Target region group: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- AWS region: \`$AWS_REGION\`"
  printf '%s\n' "- ALB ARN: \`$ALB_ARN\`"
  printf '%s\n' "- Access log bucket: \`$ALB_ACCESS_LOGS_BUCKET\`"
  printf '%s\n' "- Access log prefix: \`$ALB_ACCESS_LOGS_PREFIX\`"
  printf '%s\n' "- Before attributes: \`$out_dir/before-attributes.json\`"
  printf '%s\n' "- After attributes: \`$out_dir/after-attributes.json\`"
} > "$out_dir/summary.md"

/bin/cat "$out_dir/summary.md"
