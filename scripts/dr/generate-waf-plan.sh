#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=scripts/dr/common.sh
. "$SCRIPT_DIR/common.sh"

require_repo_root

TARGET_REGION_GROUP="${TARGET_REGION_GROUP:-${1:-}}"
AWS_REGION="${AWS_REGION:-}"
ALB_ARN="${ALB_ARN:-}"
WAF_NAME="${WAF_NAME:-mscqr-$TARGET_REGION_GROUP-regional-waf}"

case "$TARGET_REGION_GROUP" in
  london|mumbai|capetown) ;;
  *) echo "TARGET_REGION_GROUP must be london, mumbai, or capetown." >&2; exit 2 ;;
esac

create_artifact_dir
out_dir="$DR_ARTIFACT_DIR/waf-plan/$TARGET_REGION_GROUP"
/bin/mkdir -p "$out_dir"
plan="$out_dir/waf-plan.md"

{
  printf '# Regional WAF Plan\n\n'
  printf '%s\n' "- Target region group: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- AWS region: \`${AWS_REGION:-set-at-apply-time}\`"
  printf '%s\n' "- ALB ARN: \`${ALB_ARN:-provide-alb-arn}\`"
  printf '%s\n\n' "- Proposed WebACL name: \`$WAF_NAME\`"
  printf 'This is a plan only. It does not create or attach WAF resources.\n\n'
  printf '## Recommended managed rules\n\n'
  printf '%s\n' '- AWSManagedRulesCommonRuleSet'
  printf '%s\n' '- AWSManagedRulesKnownBadInputsRuleSet'
  printf '%s\n' '- AWSManagedRulesAmazonIpReputationList'
  printf '%s\n\n' '- Rate-based rule scoped to `/api/` after baseline traffic is measured.'
  printf '## Example apply steps, for a separate approved WAF change\n\n'
  printf '1. Create WebACL in `%s` with count mode first.\n' "${AWS_REGION:-<region>}"
  printf '2. Associate WebACL to `%s`.\n' "${ALB_ARN:-<alb-arn>}"
  printf '3. Review sampled requests for false positives.\n'
  printf '4. Move selected rules from count to block after approval.\n'
} > "$plan"

/bin/cat "$plan"
