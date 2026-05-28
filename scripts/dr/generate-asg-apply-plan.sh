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
ASG_ASSOCIATE_PUBLIC_IP="${ASG_ASSOCIATE_PUBLIC_IP:-false}"
ASG_KEY_NAME="${ASG_KEY_NAME:-}"
ASG_REPO_URL="${ASG_REPO_URL:-}"
ASG_REPO_BRANCH="${ASG_REPO_BRANCH:-main}"
ASG_REPO_DIR="${ASG_REPO_DIR:-/home/ubuntu/genuine-scan-main}"
ROLLING_POLICY_CHECKLIST_PATH="${ROLLING_POLICY_CHECKLIST_PATH:-documents/ops/aws-asg-rolling-deploy-policy.checklist.json}"

case "$TARGET_REGION_GROUP" in
  mumbai|capetown) ;;
  *) echo "TARGET_REGION_GROUP must be mumbai or capetown." >&2; exit 2 ;;
esac

case "$TARGET_REGION_GROUP:$AWS_REGION" in
  mumbai:ap-south-1|capetown:af-south-1) ;;
  *) echo "AWS_REGION does not match TARGET_REGION_GROUP." >&2; exit 2 ;;
esac

if [ -z "$ASG_WEB_INSTANCE_PROFILE_ARN" ] && [ -z "$ASG_WEB_INSTANCE_PROFILE_NAME" ]; then
  echo "ASG_WEB_INSTANCE_PROFILE_ARN or ASG_WEB_INSTANCE_PROFILE_NAME is required for ASG web launch-template planning." >&2
  exit 2
fi

case "$ASG_ASSOCIATE_PUBLIC_IP" in
  true|false) ;;
  *) echo "ASG_ASSOCIATE_PUBLIC_IP must be true or false." >&2; exit 2 ;;
esac

case "$ASG_KEY_NAME" in
  *[[:space:]]*) echo "ASG_KEY_NAME must not contain whitespace." >&2; exit 2 ;;
esac
if [ -z "$ASG_REPO_URL" ]; then
  echo "ASG_REPO_URL is required for self-sufficient ASG web-node bootstrap." >&2
  exit 2
fi
case "$ASG_REPO_URL" in
  *[[:space:]]*|*@*) echo "ASG_REPO_URL must be a non-secret URL without whitespace or embedded credentials." >&2; exit 2 ;;
esac
case "$ASG_REPO_BRANCH" in
  ""|*[[:space:]]*) echo "ASG_REPO_BRANCH must be non-empty and must not contain whitespace." >&2; exit 2 ;;
esac
case "$ASG_REPO_DIR" in
  ""|*[[:space:]]*) echo "ASG_REPO_DIR must be non-empty and must not contain whitespace." >&2; exit 2 ;;
esac

policy_env_file="$(mktemp "${TMPDIR:-/tmp}/mscqr-asg-rolling-policy.XXXXXX")"
trap 'rm -f "$policy_env_file"' EXIT HUP INT TERM
render_asg_rolling_policy_env "$ROLLING_POLICY_CHECKLIST_PATH" "$TARGET_REGION_GROUP" "$policy_env_file"
# shellcheck disable=SC1090
. "$policy_env_file"

MIN_SIZE="${MIN_SIZE:-$ASG_POLICY_MIN_SIZE_INITIAL}"
DESIRED_CAPACITY="${DESIRED_CAPACITY:-$ASG_POLICY_DESIRED_CAPACITY_INITIAL}"
MAX_SIZE="${MAX_SIZE:-$ASG_POLICY_MAX_SIZE_INITIAL}"

[ "$MIN_SIZE" = "$ASG_POLICY_MIN_SIZE_INITIAL" ] || { echo "MIN_SIZE must match ASG policy value $ASG_POLICY_MIN_SIZE_INITIAL for the first rollout." >&2; exit 2; }
[ "$DESIRED_CAPACITY" = "$ASG_POLICY_DESIRED_CAPACITY_INITIAL" ] || { echo "DESIRED_CAPACITY must match ASG policy value $ASG_POLICY_DESIRED_CAPACITY_INITIAL for the first rollout." >&2; exit 2; }
[ "$MAX_SIZE" = "$ASG_POLICY_MAX_SIZE_INITIAL" ] || { echo "MAX_SIZE must match ASG policy value $ASG_POLICY_MAX_SIZE_INITIAL for the first rollout." >&2; exit 2; }

create_artifact_dir
out_dir="$DR_ARTIFACT_DIR/asg-apply-plan/$TARGET_REGION_GROUP"
/bin/mkdir -p "$out_dir"

if [ -n "$SOURCE_INSTANCE_ID" ]; then
  aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$SOURCE_INSTANCE_ID" --output json > "$out_dir/source-instance.json"
  if [ -z "$SOURCE_AMI" ]; then SOURCE_AMI="$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$SOURCE_INSTANCE_ID" --query 'Reservations[0].Instances[0].ImageId' --output text)"; fi
  if [ -z "$SOURCE_INSTANCE_TYPE" ]; then SOURCE_INSTANCE_TYPE="$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$SOURCE_INSTANCE_ID" --query 'Reservations[0].Instances[0].InstanceType' --output text)"; fi
  if [ -z "$SOURCE_SECURITY_GROUP" ]; then SOURCE_SECURITY_GROUP="$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$SOURCE_INSTANCE_ID" --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text)"; fi
fi

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

write_asg_web_launch_template_json \
  "$out_dir/proposed-launch-template.json" \
  "$launch_template_name" \
  "$SOURCE_AMI" \
  "$SOURCE_INSTANCE_TYPE" \
  "$SOURCE_SECURITY_GROUP" \
  "$TARGET_REGION_GROUP" \
  "$AWS_REGION" \
  "$ASG_WEB_INSTANCE_PROFILE_ARN" \
  "$ASG_WEB_INSTANCE_PROFILE_NAME" \
  "$ASG_ASSOCIATE_PUBLIC_IP" \
  "$ASG_KEY_NAME" \
  "$ASG_REPO_URL" \
  "$ASG_REPO_BRANCH" \
  "$ASG_REPO_DIR" \
  wrapper
validate_asg_launch_template_json "$out_dir/proposed-launch-template.json" wrapper "$ASG_ASSOCIATE_PUBLIC_IP" "$SOURCE_SECURITY_GROUP" "$ASG_KEY_NAME" "$ASG_REPO_URL" "$ASG_REPO_BRANCH" "$ASG_REPO_DIR"

/bin/cat > "$out_dir/proposed-asg.json" <<JSON
{
  "AutoScalingGroupName": "$asg_name",
  "LaunchTemplateName": "$launch_template_name",
  "MinSize": $MIN_SIZE,
  "DesiredCapacity": $DESIRED_CAPACITY,
  "MaxSize": $MAX_SIZE,
  "HealthCheckType": "$ASG_POLICY_HEALTH_CHECK_TYPE",
  "HealthCheckGracePeriod": $ASG_POLICY_HEALTH_CHECK_GRACE_PERIOD_SECONDS,
  "DefaultInstanceWarmup": $ASG_POLICY_DEFAULT_INSTANCE_WARMUP_SECONDS,
  "VPCZoneIdentifier": "$selected_subnet_csv",
  "TargetGroupARNs": ["$TARGET_GROUP_ARN"]
}
JSON

{
  printf '# ASG Apply Plan\n\n'
  printf '%s\n' "- Target region group: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- AWS region: \`$AWS_REGION\`"
  printf '%s\n' "- Source instance: \`$SOURCE_INSTANCE_ID\`"
  printf '%s\n' "- Source AMI: \`$SOURCE_AMI\`"
  printf '%s\n' "- Source instance type: \`$SOURCE_INSTANCE_TYPE\`"
  printf '%s\n' "- Source security group: \`$SOURCE_SECURITY_GROUP\`"
  if [ -n "$ASG_WEB_INSTANCE_PROFILE_ARN" ]; then
    printf '%s\n' "- ASG web instance profile: explicit ARN provided"
  else
    printf '%s\n' "- ASG web instance profile name: \`$ASG_WEB_INSTANCE_PROFILE_NAME\`"
  fi
  printf '%s\n' "- Associate public IP: \`$ASG_ASSOCIATE_PUBLIC_IP\`"
  if [ "$ASG_ASSOCIATE_PUBLIC_IP" = "true" ]; then
    printf '%s\n' "- Launch template networking: \`NetworkInterfaces[0].AssociatePublicIpAddress=true\` with \`Groups=[$SOURCE_SECURITY_GROUP]\` and no top-level \`SecurityGroupIds\`"
  else
    printf '%s\n' "- Launch template networking: top-level \`SecurityGroupIds=[$SOURCE_SECURITY_GROUP]\` and no \`NetworkInterfaces\`"
  fi
  if [ -n "$ASG_KEY_NAME" ]; then
    printf '%s\n' "- KeyName: provided (\`$ASG_KEY_NAME\`)"
  else
    printf '%s\n' "- KeyName: not provided"
  fi
  printf '%s\n' "- Repository URL: \`$ASG_REPO_URL\`"
  printf '%s\n' "- Repository branch: \`$ASG_REPO_BRANCH\`"
  printf '%s\n' "- Repository directory: \`$ASG_REPO_DIR\`"
  printf '%s\n' "- Package bootstrap: enabled; UserData installs/checks git, Docker, and docker compose before cloning/updating the repo."
  printf '%s\n' "- Launch template UserData: base64 bootstrap that installs prerequisites, clones or refreshes \`$ASG_REPO_DIR\`, then runs \`scripts/dr/bootstrap-asg-web-node.sh \"$TARGET_REGION_GROUP\" \"$AWS_REGION\"\`"
  printf '%s\n' "- Mumbai debug retry: use \`ASG_ASSOCIATE_PUBLIC_IP=true\`, \`ASG_KEY_NAME=mscqr-prod-mumbai\`, \`ASG_REPO_URL=https://github.com/T-ej2003/genuine-scan-main.git\`, \`ASG_REPO_BRANCH=main\`, and \`ASG_REPO_DIR=/home/ubuntu/genuine-scan-main\` only for the no-DNS validation/debug pass."
  printf '%s\n' "- Selected app subnets: \`$selected_subnet_ids\`"
  printf '%s\n' "- Proposed ASG capacity: \`min=$MIN_SIZE desired=$DESIRED_CAPACITY max=$MAX_SIZE\`"
  printf '%s\n' "- Health check type: \`$ASG_POLICY_HEALTH_CHECK_TYPE\`"
  printf '%s\n' "- Health check grace period: \`$ASG_POLICY_HEALTH_CHECK_GRACE_PERIOD_SECONDS\` seconds"
  printf '%s\n' "- Default instance warmup: \`$ASG_POLICY_DEFAULT_INSTANCE_WARMUP_SECONDS\` seconds"
  printf '%s\n' "- Cold bootstrap policy: grace/warmup account for fresh Ubuntu package install, image build, and frontend \`/healthz\` reaching roughly 295 seconds in Mumbai evidence."
  printf '%s\n' "- Target deregistration delay required on target group: \`$ASG_POLICY_DEREGISTRATION_DELAY_SECONDS\` seconds"
  printf '%s\n' "- Instance refresh min healthy percentage: \`$ASG_POLICY_INSTANCE_REFRESH_MIN_HEALTHY_PERCENTAGE\`"
  printf '%s\n' "- Instance refresh max healthy percentage: \`$ASG_POLICY_INSTANCE_REFRESH_MAX_HEALTHY_PERCENTAGE\`"
  printf '%s\n' "- Instance refresh checkpoints: \`$ASG_POLICY_INSTANCE_REFRESH_CHECKPOINT_PERCENTAGES_CSV\` with \`$ASG_POLICY_INSTANCE_REFRESH_CHECKPOINT_DELAY_SECONDS\` second wait"
  printf '%s\n' "- Required healthy current ASG targets after apply and replacement: \`$ASG_POLICY_TARGET_GROUP_HEALTH_REQUIRED\`; legacy/source targets in the same target group do not satisfy ASG readiness."
  printf '%s\n' "- Rolling policy checklist: \`$ROLLING_POLICY_CHECKLIST_PATH\`"
  printf '%s\n' "- Remaining live go/no-go: create and attach the ASG, then run a no-DNS replacement-instance drill with CloudWatch and target-health evidence."
  printf '%s\n' "- Production DNS cutover: not allowed during ASG validation."
  printf '\nRisks to review before ASG apply: node-local Redis, MinIO, app secrets, migrations, sessions, filesystem state, background workers, sticky behavior, and unproven replacement-instance behavior.\n'
} > "$out_dir/asg-apply-plan.md"

/bin/cat "$out_dir/asg-apply-plan.md"
