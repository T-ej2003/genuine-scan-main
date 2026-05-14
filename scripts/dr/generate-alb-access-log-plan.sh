#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=scripts/dr/common.sh
. "$SCRIPT_DIR/common.sh"

require_repo_root

TARGET_REGION_GROUP="${TARGET_REGION_GROUP:-${1:-}}"
AWS_REGION="${AWS_REGION:-}"
ALB_ARN="${ALB_ARN:-}"
ACCESS_LOGS_BUCKET="${ACCESS_LOGS_BUCKET:-<approved-alb-access-logs-bucket>}"
ACCESS_LOGS_PREFIX="${ACCESS_LOGS_PREFIX:-mscqr/alb/$TARGET_REGION_GROUP}"

case "$TARGET_REGION_GROUP" in
  london|mumbai|capetown) ;;
  *) echo "TARGET_REGION_GROUP must be london, mumbai, or capetown." >&2; exit 2 ;;
esac

create_artifact_dir
out_dir="$DR_ARTIFACT_DIR/alb-access-log-plan/$TARGET_REGION_GROUP"
/bin/mkdir -p "$out_dir"
plan="$out_dir/alb-access-log-plan.md"

{
  printf '# ALB Access Log Plan\n\n'
  printf '%s\n' "- Target region group: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- AWS region: \`${AWS_REGION:-set-at-apply-time}\`"
  printf '%s\n' "- ALB ARN: \`${ALB_ARN:-provide-alb-arn}\`"
  printf '%s\n' "- S3 bucket: \`$ACCESS_LOGS_BUCKET\`"
  printf '%s\n\n' "- S3 prefix: \`$ACCESS_LOGS_PREFIX\`"
  printf 'This is a plan only. It does not enable access logs or write S3 objects.\n\n'
  printf '## Approval checks\n\n'
  printf '%s\n' '- Bucket exists in the approved logging account/region.'
  printf '%s\n' '- Bucket policy allows the regional ALB log delivery principal.'
  printf '%s\n' '- Lifecycle retention is approved.'
  printf '%s\n\n' '- No production application bucket is reused for ALB logs.'
  printf '## Example apply command, for a separate approved logging change\n\n'
  printf '```sh\n'
  printf '# aws elbv2 modify-load-balancer-attributes --region %s --load-balancer-arn %s --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=%s Key=access_logs.s3.prefix,Value=%s\n' "${AWS_REGION:-<region>}" "${ALB_ARN:-<alb-arn>}" "$ACCESS_LOGS_BUCKET" "$ACCESS_LOGS_PREFIX"
  printf '```\n'
} > "$plan"

/bin/cat "$plan"
