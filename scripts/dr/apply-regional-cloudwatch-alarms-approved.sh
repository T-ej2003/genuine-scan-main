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
TARGET_GROUP_ARN="${TARGET_GROUP_ARN:-}"
SOURCE_INSTANCE_ID="${SOURCE_INSTANCE_ID:-${INSTANCE_ID:-}}"
SNS_TOPIC_ARN="${SNS_TOPIC_ARN:-}"
CONFIRM_CLOUDWATCH_ALARM_APPLY="${CONFIRM_CLOUDWATCH_ALARM_APPLY:-}"

case "$TARGET_REGION_GROUP" in
  mumbai|capetown) ;;
  *) echo "TARGET_REGION_GROUP must be mumbai or capetown." >&2; exit 2 ;;
esac

case "$TARGET_REGION_GROUP:$AWS_REGION" in
  mumbai:ap-south-1|capetown:af-south-1) ;;
  *) echo "AWS_REGION does not match TARGET_REGION_GROUP." >&2; exit 2 ;;
esac

if [ "$CONFIRM_CLOUDWATCH_ALARM_APPLY" != "I_APPROVE_CLOUDWATCH_ALARM_APPLY" ]; then
  echo "Refusing CloudWatch alarm apply without CONFIRM_CLOUDWATCH_ALARM_APPLY=I_APPROVE_CLOUDWATCH_ALARM_APPLY." >&2
  exit 2
fi

if [ -z "$ALB_ARN" ] || [ -z "$TARGET_GROUP_ARN" ] || [ -z "$SOURCE_INSTANCE_ID" ]; then
  echo "ALB_ARN, TARGET_GROUP_ARN, and SOURCE_INSTANCE_ID are required." >&2
  exit 2
fi

create_artifact_dir
out_dir="$DR_ARTIFACT_DIR/hardening-cloudwatch-alarms/$TARGET_REGION_GROUP"
/bin/mkdir -p "$out_dir"

lb_dimension="${ALB_ARN#*loadbalancer/}"
tg_dimension="${TARGET_GROUP_ARN#*targetgroup/}"
alarm_names_file="$out_dir/alarm-names.txt"
: > "$alarm_names_file"

alarm_actions_args=""
if [ -n "$SNS_TOPIC_ARN" ]; then
  alarm_actions_args="--alarm-actions $SNS_TOPIC_ARN"
else
  echo "Warning: SNS_TOPIC_ARN is empty; alarms will be created without alarm actions."
fi

put_alarm() {
  name="$1"
  shift
  printf '%s\n' "$name" >> "$alarm_names_file"
  # shellcheck disable=SC2086
  aws cloudwatch put-metric-alarm "$@" $alarm_actions_args
}

prefix="MSCQR-$TARGET_REGION_GROUP"

put_alarm "$prefix-ALB-5XX" \
  --region "$AWS_REGION" \
  --alarm-name "$prefix-ALB-5XX" \
  --namespace AWS/ApplicationELB \
  --metric-name HTTPCode_ELB_5XX_Count \
  --dimensions Name=LoadBalancer,Value="$lb_dimension" \
  --statistic Sum \
  --period 60 \
  --evaluation-periods 2 \
  --threshold 0 \
  --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching

put_alarm "$prefix-Target-5XX" \
  --region "$AWS_REGION" \
  --alarm-name "$prefix-Target-5XX" \
  --namespace AWS/ApplicationELB \
  --metric-name HTTPCode_Target_5XX_Count \
  --dimensions Name=LoadBalancer,Value="$lb_dimension" Name=TargetGroup,Value="$tg_dimension" \
  --statistic Sum \
  --period 60 \
  --evaluation-periods 2 \
  --threshold 0 \
  --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching

put_alarm "$prefix-UnhealthyHosts" \
  --region "$AWS_REGION" \
  --alarm-name "$prefix-UnhealthyHosts" \
  --namespace AWS/ApplicationELB \
  --metric-name UnHealthyHostCount \
  --dimensions Name=LoadBalancer,Value="$lb_dimension" Name=TargetGroup,Value="$tg_dimension" \
  --statistic Maximum \
  --period 60 \
  --evaluation-periods 2 \
  --threshold 0 \
  --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching

put_alarm "$prefix-TargetResponseTime-p95" \
  --region "$AWS_REGION" \
  --alarm-name "$prefix-TargetResponseTime-p95" \
  --namespace AWS/ApplicationELB \
  --metric-name TargetResponseTime \
  --dimensions Name=LoadBalancer,Value="$lb_dimension" Name=TargetGroup,Value="$tg_dimension" \
  --extended-statistic p95 \
  --period 60 \
  --evaluation-periods 3 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching

put_alarm "$prefix-EC2-CPU-70" \
  --region "$AWS_REGION" \
  --alarm-name "$prefix-EC2-CPU-70" \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value="$SOURCE_INSTANCE_ID" \
  --statistic Average \
  --period 300 \
  --evaluation-periods 3 \
  --threshold 70 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data missing

alarm_names="$(/usr/bin/tr '\n' ' ' < "$alarm_names_file")"
# shellcheck disable=SC2086
aws cloudwatch describe-alarms --region "$AWS_REGION" --alarm-names $alarm_names --output json > "$out_dir/describe-alarms.json"

{
  printf '# CloudWatch Alarm Apply Evidence\n\n'
  printf '%s\n' "- Target region group: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- AWS region: \`$AWS_REGION\`"
  printf '%s\n' "- SNS topic configured: \`$(if [ -n "$SNS_TOPIC_ARN" ]; then printf yes; else printf no; fi)\`"
  printf '%s\n' "- Alarm names file: \`$alarm_names_file\`"
  printf '%s\n' "- Alarm describe output: \`$out_dir/describe-alarms.json\`"
} > "$out_dir/summary.md"

/bin/cat "$out_dir/summary.md"
