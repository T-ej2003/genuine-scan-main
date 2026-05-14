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
ALB_DNS_NAME="${ALB_DNS_NAME:-}"
TARGET_GROUP_ARN="${TARGET_GROUP_ARN:-}"
DOMAIN_NAME="${DOMAIN_NAME:-www.mscqr.com}"
TEST_HOSTNAME="${TEST_HOSTNAME:-}"
HEALTH_CHECK_PATH="${HEALTH_CHECK_PATH:-/healthz}"

expected_region() {
  case "$1" in
    london) printf '%s\n' "eu-west-2" ;;
    mumbai) printf '%s\n' "ap-south-1" ;;
    capetown) printf '%s\n' "af-south-1" ;;
    *) return 1 ;;
  esac
}

case "$TARGET_REGION_GROUP" in
  london|mumbai|capetown) ;;
  *) echo "TARGET_REGION_GROUP must be london, mumbai, or capetown." >&2; exit 2 ;;
esac

if [ -z "$AWS_REGION" ]; then
  AWS_REGION="$(expected_region "$TARGET_REGION_GROUP")"
fi
if [ "$AWS_REGION" != "$(expected_region "$TARGET_REGION_GROUP")" ]; then
  echo "AWS_REGION $AWS_REGION does not match $TARGET_REGION_GROUP." >&2
  exit 2
fi

create_artifact_dir
out_dir="$DR_ARTIFACT_DIR/regional-alb-health/$TARGET_REGION_GROUP"
/bin/mkdir -p "$out_dir"

echo "Running read-only regional ALB health verification for $TARGET_REGION_GROUP."
echo "No DNS records, AWS resources, RDS data, or S3 objects will be changed."

if [ -n "$ALB_ARN" ]; then
  aws elbv2 describe-load-balancers \
    --region "$AWS_REGION" \
    --load-balancer-arns "$ALB_ARN" \
    --output json > "$out_dir/load-balancer.json"
  aws elbv2 describe-listeners \
    --region "$AWS_REGION" \
    --load-balancer-arn "$ALB_ARN" \
    --output json > "$out_dir/listeners.json"
  if [ -z "$ALB_DNS_NAME" ]; then
    ALB_DNS_NAME="$(aws elbv2 describe-load-balancers --region "$AWS_REGION" --load-balancer-arns "$ALB_ARN" --query 'LoadBalancers[0].DNSName' --output text)"
  fi
fi

if [ -n "$TARGET_GROUP_ARN" ]; then
  aws elbv2 describe-target-health \
    --region "$AWS_REGION" \
    --target-group-arn "$TARGET_GROUP_ARN" \
    --output json > "$out_dir/target-health.json"
fi

curl_status="not-run"
: > "$out_dir/curl.log"

if [ -n "$TEST_HOSTNAME" ]; then
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS "https://$TEST_HOSTNAME$HEALTH_CHECK_PATH" > "$out_dir/curl-body.txt" 2> "$out_dir/curl.log"; then
      curl_status="passed-regional-test-hostname"
    else
      curl_status="failed-regional-test-hostname"
    fi
  fi
elif [ -n "$ALB_DNS_NAME" ] && command -v dig >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
  alb_ip="$(dig +short "$ALB_DNS_NAME" | /usr/bin/awk 'NF { print; exit }')"
  if [ -n "$alb_ip" ]; then
    printf '%s\n' "$alb_ip" > "$out_dir/alb-first-ip.txt"
    if curl -fsS --resolve "$DOMAIN_NAME:443:$alb_ip" "https://$DOMAIN_NAME$HEALTH_CHECK_PATH" > "$out_dir/curl-body.txt" 2> "$out_dir/curl.log"; then
      curl_status="passed-resolve"
    else
      curl_status="failed-resolve"
    fi
  fi
fi

summary="$out_dir/summary.md"
{
  printf '# Regional ALB Health Verification\n\n'
  printf '%s\n' "- Target region group: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- AWS region: \`$AWS_REGION\`"
  printf '%s\n' "- ALB ARN: \`${ALB_ARN:-not-provided}\`"
  printf '%s\n' "- ALB DNS name: \`${ALB_DNS_NAME:-not-provided}\`"
  printf '%s\n' "- Target group ARN: \`${TARGET_GROUP_ARN:-not-provided}\`"
  printf '%s\n' "- Health path: \`$HEALTH_CHECK_PATH\`"
  printf '%s\n' "- HTTPS smoke status: \`$curl_status\`"
  printf '\nThe raw ALB DNS hostname is not expected to pass certificate hostname verification. Use a regional alias or curl `--resolve` against `%s`.\n' "$DOMAIN_NAME"
} > "$summary"

/bin/cat "$summary"
