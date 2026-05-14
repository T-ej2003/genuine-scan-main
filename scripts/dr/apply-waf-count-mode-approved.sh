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
WAF_WEB_ACL_NAME="${WAF_WEB_ACL_NAME:-${WAF_NAME:-mscqr-$TARGET_REGION_GROUP-regional-waf}}"
CONFIRM_WAF_COUNT_MODE_APPLY="${CONFIRM_WAF_COUNT_MODE_APPLY:-}"

case "$TARGET_REGION_GROUP" in
  mumbai|capetown) ;;
  *) echo "TARGET_REGION_GROUP must be mumbai or capetown." >&2; exit 2 ;;
esac

case "$TARGET_REGION_GROUP:$AWS_REGION" in
  mumbai:ap-south-1|capetown:af-south-1) ;;
  *) echo "AWS_REGION does not match TARGET_REGION_GROUP." >&2; exit 2 ;;
esac

if [ "$CONFIRM_WAF_COUNT_MODE_APPLY" != "I_APPROVE_WAF_COUNT_MODE_APPLY" ]; then
  echo "Refusing WAF COUNT-mode apply without CONFIRM_WAF_COUNT_MODE_APPLY=I_APPROVE_WAF_COUNT_MODE_APPLY." >&2
  exit 2
fi

if [ -z "$ALB_ARN" ]; then
  echo "ALB_ARN is required." >&2
  exit 2
fi

create_artifact_dir
out_dir="$DR_ARTIFACT_DIR/hardening-waf-count-mode/$TARGET_REGION_GROUP"
/bin/mkdir -p "$out_dir"

rules_file="$out_dir/waf-count-rules.json"
visibility_file="$out_dir/waf-visibility.json"

node --input-type=module - "$TARGET_REGION_GROUP" "$rules_file" "$visibility_file" <<'NODE'
import fs from "node:fs";
const [regionGroup, rulesPath, visibilityPath] = process.argv.slice(2);
const metricPrefix = `MSCQR${regionGroup.replace(/[^A-Za-z0-9]/g, "")}`;
const visibility = (metricName) => ({
  SampledRequestsEnabled: true,
  CloudWatchMetricsEnabled: true,
  MetricName: metricName,
});
const managedRule = (name, priority, metricName) => ({
  Name: name,
  Priority: priority,
  Statement: {
    ManagedRuleGroupStatement: {
      VendorName: "AWS",
      Name: name,
    },
  },
  OverrideAction: { Count: {} },
  VisibilityConfig: visibility(metricName),
});
const rules = [
  managedRule("AWSManagedRulesCommonRuleSet", 10, `${metricPrefix}CommonCount`),
  managedRule("AWSManagedRulesKnownBadInputsRuleSet", 20, `${metricPrefix}KnownBadCount`),
  managedRule("AWSManagedRulesAmazonIpReputationList", 30, `${metricPrefix}IpReputationCount`),
  {
    Name: "MSCQRApiRateLimitCount",
    Priority: 40,
    Statement: {
      RateBasedStatement: {
        Limit: 2000,
        AggregateKeyType: "IP",
        ScopeDownStatement: {
          ByteMatchStatement: {
            SearchString: "/api/",
            FieldToMatch: { UriPath: {} },
            TextTransformations: [{ Priority: 0, Type: "NONE" }],
            PositionalConstraint: "STARTS_WITH",
          },
        },
      },
    },
    Action: { Count: {} },
    VisibilityConfig: visibility(`${metricPrefix}ApiRateLimitCount`),
  },
];
fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));
fs.writeFileSync(visibilityPath, JSON.stringify(visibility(`${metricPrefix}WebAcl`), null, 2));
NODE

web_acl_id="$(aws wafv2 list-web-acls \
  --region "$AWS_REGION" \
  --scope REGIONAL \
  --query "WebACLs[?Name=='$WAF_WEB_ACL_NAME'].Id | [0]" \
  --output text)"

if [ "$web_acl_id" = "None" ] || [ -z "$web_acl_id" ]; then
  aws wafv2 create-web-acl \
    --region "$AWS_REGION" \
    --name "$WAF_WEB_ACL_NAME" \
    --scope REGIONAL \
    --default-action Allow={} \
    --rules "file://$rules_file" \
    --visibility-config "file://$visibility_file" \
    --tags Key=Project,Value=MSCQR Key=Purpose,Value=DR Key=RegionGroup,Value="$TARGET_REGION_GROUP" \
    --output json > "$out_dir/create-web-acl.json"
  web_acl_id="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); console.log(p.Summary.Id)' "$out_dir/create-web-acl.json")"
else
  lock_token="$(aws wafv2 get-web-acl \
    --region "$AWS_REGION" \
    --scope REGIONAL \
    --name "$WAF_WEB_ACL_NAME" \
    --id "$web_acl_id" \
    --query LockToken \
    --output text)"
  aws wafv2 update-web-acl \
    --region "$AWS_REGION" \
    --scope REGIONAL \
    --name "$WAF_WEB_ACL_NAME" \
    --id "$web_acl_id" \
    --lock-token "$lock_token" \
    --default-action Allow={} \
    --rules "file://$rules_file" \
    --visibility-config "file://$visibility_file" \
    --output json > "$out_dir/update-web-acl.json"
fi

web_acl_arn="$(aws wafv2 get-web-acl \
  --region "$AWS_REGION" \
  --scope REGIONAL \
  --name "$WAF_WEB_ACL_NAME" \
  --id "$web_acl_id" \
  --query 'WebACL.ARN' \
  --output text)"

aws wafv2 associate-web-acl \
  --region "$AWS_REGION" \
  --web-acl-arn "$web_acl_arn" \
  --resource-arn "$ALB_ARN" \
  --output json > "$out_dir/associate-web-acl.json" 2>"$out_dir/associate-web-acl.err" || {
    if /usr/bin/grep -q WAFUnavailableEntityException "$out_dir/associate-web-acl.err"; then
      /bin/cat "$out_dir/associate-web-acl.err" >&2
      exit 1
    fi
    if ! /usr/bin/grep -q WAFDuplicateItemException "$out_dir/associate-web-acl.err"; then
      /bin/cat "$out_dir/associate-web-acl.err" >&2
      exit 1
    fi
    printf '{"status":"already-associated"}\n' > "$out_dir/associate-web-acl.json"
  }

aws wafv2 get-web-acl \
  --region "$AWS_REGION" \
  --scope REGIONAL \
  --name "$WAF_WEB_ACL_NAME" \
  --id "$web_acl_id" \
  --output json > "$out_dir/web-acl.json"
aws wafv2 get-web-acl-for-resource \
  --region "$AWS_REGION" \
  --resource-arn "$ALB_ARN" \
  --output json > "$out_dir/web-acl-association.json"

{
  printf '# WAF COUNT Mode Apply Evidence\n\n'
  printf '%s\n' "- Target region group: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- AWS region: \`$AWS_REGION\`"
  printf '%s\n' "- WebACL name: \`$WAF_WEB_ACL_NAME\`"
  printf '%s\n' "- WebACL ARN: \`$web_acl_arn\`"
  printf '%s\n' "- ALB ARN: \`$ALB_ARN\`"
  printf '\nRules are configured in COUNT mode only. Review sampled requests in AWS WAF before any future BLOCK-mode change.\n'
} > "$out_dir/summary.md"

/bin/cat "$out_dir/summary.md"
