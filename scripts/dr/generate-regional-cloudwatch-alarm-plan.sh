#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=scripts/dr/common.sh
. "$SCRIPT_DIR/common.sh"

require_repo_root

TARGET_REGION_GROUP="${TARGET_REGION_GROUP:-${1:-}}"
AWS_REGION="${AWS_REGION:-}"
ALB_ARN="${ALB_ARN:-}"
TARGET_GROUP_ARN="${TARGET_GROUP_ARN:-}"
INSTANCE_ID="${INSTANCE_ID:-}"
SNS_TOPIC_ARN="${SNS_TOPIC_ARN:-<approved-sns-topic-arn>}"

case "$TARGET_REGION_GROUP" in
  london|mumbai|capetown) ;;
  *) echo "TARGET_REGION_GROUP must be london, mumbai, or capetown." >&2; exit 2 ;;
esac

create_artifact_dir
out_dir="$DR_ARTIFACT_DIR/cloudwatch-alarm-plan/$TARGET_REGION_GROUP"
/bin/mkdir -p "$out_dir"

lb_dimension="${ALB_ARN#*loadbalancer/}"
tg_dimension="${TARGET_GROUP_ARN#*targetgroup/}"
plan="$out_dir/cloudwatch-alarm-plan.md"

{
  printf '# CloudWatch Alarm Plan\n\n'
  printf '%s\n' "- Target region group: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- AWS region: \`${AWS_REGION:-set-at-apply-time}\`"
  printf '%s\n' "- ALB dimension: \`${lb_dimension:-provide-alb-arn}\`"
  printf '%s\n' "- Target group dimension: \`${tg_dimension:-provide-target-group-arn}\`"
  printf '%s\n' "- EC2 instance ID: \`${INSTANCE_ID:-provide-instance-id}\`"
  printf '%s\n\n' "- SNS topic ARN: \`$SNS_TOPIC_ARN\`"
  printf '## Recommended alarms\n\n'
  printf '- ALB `HTTPCode_ELB_5XX_Count` > 0 for 2 periods.\n'
  printf '- Target `HTTPCode_Target_5XX_Count` > 0 for 2 periods.\n'
  printf '- `UnHealthyHostCount` >= 1 for 2 periods.\n'
  printf '- `TargetResponseTime` p95 >= 1 second for 3 periods.\n'
  printf '- EC2 `CPUUtilization` >= 70%% for 3 periods.\n'
  printf '- Disk `disk_used_percent` >= 80%% if CloudWatch Agent publishes `CWAgent` metrics.\n\n'
  printf '## Example apply commands, for a separately approved monitoring apply change\n\n'
  printf '```sh\n'
  printf '# aws cloudwatch put-metric-alarm --region %s --alarm-name MSCQR-%s-ALB-5XX --namespace AWS/ApplicationELB --metric-name HTTPCode_ELB_5XX_Count --dimensions Name=LoadBalancer,Value=%s --statistic Sum --period 60 --evaluation-periods 2 --threshold 0 --comparison-operator GreaterThanThreshold --alarm-actions %s\n' "${AWS_REGION:-<region>}" "$TARGET_REGION_GROUP" "${lb_dimension:-<load-balancer-dimension>}" "$SNS_TOPIC_ARN"
  printf '# aws cloudwatch put-metric-alarm --region %s --alarm-name MSCQR-%s-UnhealthyHosts --namespace AWS/ApplicationELB --metric-name UnHealthyHostCount --dimensions Name=LoadBalancer,Value=%s Name=TargetGroup,Value=%s --statistic Maximum --period 60 --evaluation-periods 2 --threshold 0 --comparison-operator GreaterThanThreshold --alarm-actions %s\n' "${AWS_REGION:-<region>}" "$TARGET_REGION_GROUP" "${lb_dimension:-<load-balancer-dimension>}" "${tg_dimension:-<target-group-dimension>}" "$SNS_TOPIC_ARN"
  printf '```\n'
} > "$plan"

/bin/cat "$plan"
