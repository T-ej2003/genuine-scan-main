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
SOURCE_INSTANCE_ID="${SOURCE_INSTANCE_ID:-${INSTANCE_ID:-}}"
SOURCE_AMI="${SOURCE_AMI:-}"
SOURCE_INSTANCE_TYPE="${SOURCE_INSTANCE_TYPE:-}"
SOURCE_SECURITY_GROUP="${SOURCE_SECURITY_GROUP:-}"
TARGET_GROUP_ARN="${TARGET_GROUP_ARN:-}"
ASG_WEB_INSTANCE_PROFILE_ARN="${ASG_WEB_INSTANCE_PROFILE_ARN:-}"
ASG_WEB_INSTANCE_PROFILE_NAME="${ASG_WEB_INSTANCE_PROFILE_NAME:-}"
ROLLING_POLICY_CHECKLIST_PATH="${ROLLING_POLICY_CHECKLIST_PATH:-documents/ops/aws-asg-rolling-deploy-policy.checklist.json}"
ROLLBACK_ALARM_NAMES_CSV="${ROLLBACK_ALARM_NAMES_CSV:-}"
CONFIRM_ASG_APPLY="${CONFIRM_ASG_APPLY:-}"

case "$TARGET_REGION_GROUP" in
  mumbai|capetown) ;;
  *) echo "TARGET_REGION_GROUP must be mumbai or capetown." >&2; exit 2 ;;
esac

case "$TARGET_REGION_GROUP:$AWS_REGION" in
  mumbai:ap-south-1|capetown:af-south-1) ;;
  *) echo "AWS_REGION does not match TARGET_REGION_GROUP." >&2; exit 2 ;;
esac

if [ -z "$ASG_WEB_INSTANCE_PROFILE_ARN" ] && [ -z "$ASG_WEB_INSTANCE_PROFILE_NAME" ]; then
  echo "ASG_WEB_INSTANCE_PROFILE_ARN or ASG_WEB_INSTANCE_PROFILE_NAME is required for ASG web launch-template apply. The source instance profile is not reused automatically." >&2
  exit 2
fi

policy_env_file="$(mktemp "${TMPDIR:-/tmp}/mscqr-asg-rolling-policy.XXXXXX")"
trap 'rm -f "$policy_env_file"' EXIT HUP INT TERM
render_asg_rolling_policy_env "$ROLLING_POLICY_CHECKLIST_PATH" "$TARGET_REGION_GROUP" "$policy_env_file"
# shellcheck disable=SC1090
. "$policy_env_file"

MIN_SIZE="${MIN_SIZE:-$ASG_POLICY_MIN_SIZE_INITIAL}"
DESIRED_CAPACITY="${DESIRED_CAPACITY:-$ASG_POLICY_DESIRED_CAPACITY_INITIAL}"
MAX_SIZE="${MAX_SIZE:-$ASG_POLICY_MAX_SIZE_INITIAL}"

[ "$ASG_POLICY_STATUS" = "CONDITIONALLY_READY" ] || [ "$ASG_POLICY_STATUS" = "READY" ] || {
  echo "ASG rolling policy status must be CONDITIONALLY_READY or READY." >&2
  exit 2
}
[ "$MIN_SIZE" = "$ASG_POLICY_MIN_SIZE_INITIAL" ] || { echo "MIN_SIZE must match ASG policy value $ASG_POLICY_MIN_SIZE_INITIAL for the first rollout." >&2; exit 2; }
[ "$DESIRED_CAPACITY" = "$ASG_POLICY_DESIRED_CAPACITY_INITIAL" ] || { echo "DESIRED_CAPACITY must match ASG policy value $ASG_POLICY_DESIRED_CAPACITY_INITIAL for the first rollout." >&2; exit 2; }
[ "$MAX_SIZE" = "$ASG_POLICY_MAX_SIZE_INITIAL" ] || { echo "MAX_SIZE must match ASG policy value $ASG_POLICY_MAX_SIZE_INITIAL for the first rollout." >&2; exit 2; }
[ "$ASG_POLICY_NO_PRODUCTION_DNS_CUTOVER_DURING_VALIDATION" = "true" ] || { echo "ASG policy must forbid production DNS cutover during rollout validation." >&2; exit 2; }

if [ -z "$ROLLBACK_ALARM_NAMES_CSV" ]; then
  ROLLBACK_ALARM_NAMES_CSV="$ASG_POLICY_ROLLBACK_ALARM_NAMES_CSV"
fi

case "$ROLLBACK_ALARM_NAMES_CSV" in
  *"<"*|*">"*|"")
    echo "Refusing ASG apply without concrete rollback alarm names. Set ROLLBACK_ALARM_NAMES_CSV to reviewed CloudWatch alarm names for $TARGET_REGION_GROUP." >&2
    exit 2
    ;;
esac

if [ "$CONFIRM_ASG_APPLY" != "I_APPROVE_REGIONAL_ASG_CREATE_AND_ATTACH" ]; then
  echo "Refusing ASG apply without CONFIRM_ASG_APPLY=I_APPROVE_REGIONAL_ASG_CREATE_AND_ATTACH." >&2
  exit 2
fi

if [ -z "$SOURCE_INSTANCE_ID" ] || [ -z "$TARGET_GROUP_ARN" ]; then
  echo "SOURCE_INSTANCE_ID and TARGET_GROUP_ARN are required." >&2
  exit 2
fi

create_artifact_dir
out_dir="$DR_ARTIFACT_DIR/hardening-asg-apply/$TARGET_REGION_GROUP"
/bin/mkdir -p "$out_dir"

target_group_attributes_json="$out_dir/target-group-attributes.json"
aws elbv2 describe-target-group-attributes \
  --region "$AWS_REGION" \
  --target-group-arn "$TARGET_GROUP_ARN" \
  --output json > "$target_group_attributes_json"

deregistration_delay_seconds="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); const attrs=Object.fromEntries((p.Attributes || []).map((item) => [item.Key, item.Value])); console.log(attrs["deregistration_delay.timeout_seconds"] || "");' "$target_group_attributes_json")"
[ "$deregistration_delay_seconds" = "$ASG_POLICY_DEREGISTRATION_DELAY_SECONDS" ] || {
  echo "Target group deregistration delay must already be $ASG_POLICY_DEREGISTRATION_DELAY_SECONDS seconds before ASG apply. Found ${deregistration_delay_seconds:-unset}." >&2
  exit 2
}

aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$SOURCE_INSTANCE_ID" --output json > "$out_dir/source-instance.json"

if [ -z "$SOURCE_AMI" ]; then SOURCE_AMI="$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$SOURCE_INSTANCE_ID" --query 'Reservations[0].Instances[0].ImageId' --output text)"; fi
if [ -z "$SOURCE_INSTANCE_TYPE" ]; then SOURCE_INSTANCE_TYPE="$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$SOURCE_INSTANCE_ID" --query 'Reservations[0].Instances[0].InstanceType' --output text)"; fi
if [ -z "$SOURCE_SECURITY_GROUP" ]; then SOURCE_SECURITY_GROUP="$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$SOURCE_INSTANCE_ID" --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text)"; fi

vpc_id="$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$SOURCE_INSTANCE_ID" --query 'Reservations[0].Instances[0].VpcId' --output text)"
subnets_json="$out_dir/candidate-subnets.json"
route_tables_json="$out_dir/route-tables.json"
selected_json="$out_dir/selected-app-subnets.json"
selected_tsv="$out_dir/selected-app-subnets.tsv"
aws ec2 describe-subnets --region "$AWS_REGION" --filters "Name=vpc-id,Values=$vpc_id" --output json > "$subnets_json"
aws ec2 describe-route-tables --region "$AWS_REGION" --filters "Name=vpc-id,Values=$vpc_id" --output json > "$route_tables_json"
selected_subnet_ids="$(select_unique_az_alb_subnets "$subnets_json" "$route_tables_json" "$selected_json" "$selected_tsv")"
selected_subnet_csv="$(printf '%s\n' "$selected_subnet_ids" | /usr/bin/tr ' ' ',')"

launch_template_name="mscqr-$TARGET_REGION_GROUP-dr-lt"
asg_name="mscqr-$TARGET_REGION_GROUP-dr-asg"
launch_template_data="$out_dir/launch-template-data.json"

write_asg_web_launch_template_json \
  "$launch_template_data" \
  "$launch_template_name" \
  "$SOURCE_AMI" \
  "$SOURCE_INSTANCE_TYPE" \
  "$SOURCE_SECURITY_GROUP" \
  "$TARGET_REGION_GROUP" \
  "$AWS_REGION" \
  "$ASG_WEB_INSTANCE_PROFILE_ARN" \
  "$ASG_WEB_INSTANCE_PROFILE_NAME" \
  data
validate_asg_launch_template_json "$launch_template_data" data

launch_template_id="$(aws ec2 describe-launch-templates \
  --region "$AWS_REGION" \
  --launch-template-names "$launch_template_name" \
  --query 'LaunchTemplates[0].LaunchTemplateId' \
  --output text 2>/dev/null || true)"

if [ "$launch_template_id" = "None" ] || [ -z "$launch_template_id" ]; then
  aws ec2 create-launch-template \
    --region "$AWS_REGION" \
    --launch-template-name "$launch_template_name" \
    --launch-template-data "file://$launch_template_data" \
    --tag-specifications "ResourceType=launch-template,Tags=[{Key=Project,Value=MSCQR},{Key=Purpose,Value=DR},{Key=RegionGroup,Value=$TARGET_REGION_GROUP}]" \
    --output json > "$out_dir/create-launch-template.json"
  launch_template_id="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); console.log(p.LaunchTemplate.LaunchTemplateId)' "$out_dir/create-launch-template.json")"
  launch_template_version="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); console.log(p.LaunchTemplate.LatestVersionNumber)' "$out_dir/create-launch-template.json")"
else
  aws ec2 describe-launch-templates --region "$AWS_REGION" --launch-template-ids "$launch_template_id" --output json > "$out_dir/existing-launch-template.json"
  source_launch_template_version="$(aws ec2 describe-launch-templates --region "$AWS_REGION" --launch-template-ids "$launch_template_id" --query 'LaunchTemplates[0].LatestVersionNumber' --output text)"
  aws ec2 create-launch-template-version \
    --region "$AWS_REGION" \
    --launch-template-id "$launch_template_id" \
    --source-version "$source_launch_template_version" \
    --launch-template-data "file://$launch_template_data" \
    --output json > "$out_dir/create-launch-template-version.json"
  launch_template_version="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); console.log(p.LaunchTemplateVersion.VersionNumber)' "$out_dir/create-launch-template-version.json")"
fi

asg_exists="$(aws autoscaling describe-auto-scaling-groups \
  --region "$AWS_REGION" \
  --auto-scaling-group-names "$asg_name" \
  --query 'length(AutoScalingGroups)' \
  --output text)"

if [ "$asg_exists" = "0" ]; then
  aws autoscaling create-auto-scaling-group \
    --region "$AWS_REGION" \
    --auto-scaling-group-name "$asg_name" \
    --launch-template "LaunchTemplateId=$launch_template_id,Version=$launch_template_version" \
    --min-size "$MIN_SIZE" \
    --desired-capacity "$DESIRED_CAPACITY" \
    --max-size "$MAX_SIZE" \
    --vpc-zone-identifier "$selected_subnet_csv" \
    --target-group-arns "$TARGET_GROUP_ARN" \
    --health-check-type "$ASG_POLICY_HEALTH_CHECK_TYPE" \
    --health-check-grace-period "$ASG_POLICY_HEALTH_CHECK_GRACE_PERIOD_SECONDS" \
    --default-instance-warmup "$ASG_POLICY_DEFAULT_INSTANCE_WARMUP_SECONDS" \
    --tags ResourceId="$asg_name",ResourceType=auto-scaling-group,Key=Project,Value=MSCQR,PropagateAtLaunch=true ResourceId="$asg_name",ResourceType=auto-scaling-group,Key=Purpose,Value=DR,PropagateAtLaunch=true ResourceId="$asg_name",ResourceType=auto-scaling-group,Key=RegionGroup,Value="$TARGET_REGION_GROUP",PropagateAtLaunch=true \
    > "$out_dir/create-asg.log" 2>&1
else
  aws autoscaling describe-auto-scaling-groups --region "$AWS_REGION" --auto-scaling-group-names "$asg_name" --output json > "$out_dir/existing-asg-before.json"
  aws autoscaling update-auto-scaling-group \
    --region "$AWS_REGION" \
    --auto-scaling-group-name "$asg_name" \
    --min-size "$MIN_SIZE" \
    --desired-capacity "$DESIRED_CAPACITY" \
    --max-size "$MAX_SIZE" \
    --launch-template "LaunchTemplateId=$launch_template_id,Version=$launch_template_version" \
    --health-check-type "$ASG_POLICY_HEALTH_CHECK_TYPE" \
    --health-check-grace-period "$ASG_POLICY_HEALTH_CHECK_GRACE_PERIOD_SECONDS" \
    --default-instance-warmup "$ASG_POLICY_DEFAULT_INSTANCE_WARMUP_SECONDS" \
    > "$out_dir/update-asg.log" 2>&1
  if node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); const tg=process.argv[2]; process.exit(((p.AutoScalingGroups?.[0]?.TargetGroupARNs)||[]).includes(tg) ? 0 : 1)' "$out_dir/existing-asg-before.json" "$TARGET_GROUP_ARN"; then
    printf '%s\n' "Target group already attached to ASG." > "$out_dir/attach-target-group.log"
  else
    aws autoscaling attach-load-balancer-target-groups \
      --region "$AWS_REGION" \
      --auto-scaling-group-name "$asg_name" \
      --target-group-arns "$TARGET_GROUP_ARN" \
      > "$out_dir/attach-target-group.log" 2>&1
  fi
fi

attempts=0
healthy_count=0
while [ "$attempts" -lt 30 ]; do
  attempts=$((attempts + 1))
  aws elbv2 describe-target-health --region "$AWS_REGION" --target-group-arn "$TARGET_GROUP_ARN" --output json > "$out_dir/target-health.json"
  healthy_count="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); console.log((p.TargetHealthDescriptions || []).filter((d) => d.TargetHealth && d.TargetHealth.State === "healthy").length)' "$out_dir/target-health.json")"
  if [ "$healthy_count" -ge "$DESIRED_CAPACITY" ]; then
    break
  fi
  /bin/sleep 20
done

if [ "$healthy_count" -lt "$DESIRED_CAPACITY" ]; then
  echo "ASG apply completed, but healthy target count $healthy_count is below desired capacity $DESIRED_CAPACITY." >&2
  exit 3
fi

[ "$healthy_count" -ge "$ASG_POLICY_TARGET_GROUP_HEALTH_REQUIRED" ] || {
  echo "ASG apply completed, but healthy target count $healthy_count is below policy requirement $ASG_POLICY_TARGET_GROUP_HEALTH_REQUIRED." >&2
  exit 3
}

aws autoscaling describe-auto-scaling-groups --region "$AWS_REGION" --auto-scaling-group-names "$asg_name" --output json > "$out_dir/asg-after.json"

{
  printf 'TARGET_REGION_GROUP=%s\n' "$TARGET_REGION_GROUP"
  printf 'AWS_REGION=%s\n' "$AWS_REGION"
  printf 'ASG_NAME=%s\n' "$asg_name"
  printf 'LAUNCH_TEMPLATE_ID=%s\n' "$launch_template_id"
  printf 'LAUNCH_TEMPLATE_VERSION=%s\n' "$launch_template_version"
  printf 'TARGET_GROUP_ARN=%s\n' "$TARGET_GROUP_ARN"
  printf 'HEALTHY_TARGET_COUNT=%s\n' "$healthy_count"
  printf 'ROLLING_POLICY_CHECKLIST_PATH=%s\n' "$ROLLING_POLICY_CHECKLIST_PATH"
  printf 'ROLLBACK_ALARM_NAMES_CSV=%s\n' "$ROLLBACK_ALARM_NAMES_CSV"
} > "$out_dir/outputs.env"

/bin/cat "$out_dir/outputs.env"
