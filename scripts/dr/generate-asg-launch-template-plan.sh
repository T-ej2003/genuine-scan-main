#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=scripts/dr/common.sh
. "$SCRIPT_DIR/common.sh"

require_repo_root
require_command aws

TARGET_REGION_GROUP="${TARGET_REGION_GROUP:-${1:-}}"
AWS_REGION="${AWS_REGION:-}"
EC2_PUBLIC_IP="${EC2_PUBLIC_IP:-}"
INSTANCE_ID="${INSTANCE_ID:-}"
TARGET_GROUP_ARN="${TARGET_GROUP_ARN:-}"
ASG_MIN_SIZE="${ASG_MIN_SIZE:-2}"
ASG_DESIRED_CAPACITY="${ASG_DESIRED_CAPACITY:-2}"
ASG_MAX_SIZE="${ASG_MAX_SIZE:-4}"

case "$TARGET_REGION_GROUP" in
  london|mumbai|capetown) ;;
  *) echo "TARGET_REGION_GROUP must be london, mumbai, or capetown." >&2; exit 2 ;;
esac

create_artifact_dir
out_dir="$DR_ARTIFACT_DIR/asg-launch-template-plan/$TARGET_REGION_GROUP"
/bin/mkdir -p "$out_dir"

if [ -z "$INSTANCE_ID" ] && [ -n "$EC2_PUBLIC_IP" ]; then
  INSTANCE_ID="$(aws ec2 describe-instances --region "$AWS_REGION" --filters "Name=ip-address,Values=$EC2_PUBLIC_IP" --query 'Reservations[].Instances[].InstanceId | [0]' --output text)"
fi

if [ -n "$INSTANCE_ID" ] && [ "$INSTANCE_ID" != "None" ]; then
  aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$INSTANCE_ID" --output json > "$out_dir/source-instance.json"
  image_id="$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].ImageId' --output text)"
  instance_type="$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].InstanceType' --output text)"
  security_groups="$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].SecurityGroups[].GroupId' --output text)"
else
  image_id="<approved-ami-id>"
  instance_type="<approved-instance-type>"
  security_groups="<approved-security-group-ids>"
fi

plan="$out_dir/asg-launch-template-plan.md"
{
  printf '# ASG and Launch Template Plan\n\n'
  printf '%s\n' "- Target region group: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- AWS region: \`${AWS_REGION:-set-at-apply-time}\`"
  printf '%s\n' "- Source instance: \`${INSTANCE_ID:-not-provided}\`"
  printf '%s\n' "- Source AMI: \`$image_id\`"
  printf '%s\n' "- Source instance type: \`$instance_type\`"
  printf '%s\n' "- Source security groups: \`$security_groups\`"
  printf '%s\n' "- Target group ARN: \`${TARGET_GROUP_ARN:-provide-target-group-arn}\`"
  printf '%s\n' "- Proposed capacity: min=$ASG_MIN_SIZE desired=$ASG_DESIRED_CAPACITY max=$ASG_MAX_SIZE"
  printf '\nThis is a plan only. It does not create launch templates, ASGs, AMIs, or EC2 instances.\n\n'
  printf '## Required decisions before apply\n\n'
  printf '- Golden AMI or launch-time bootstrap source.\n'
  printf '- Approved instance type and capacity targets.\n'
  printf '- Secrets injection path for app environment.\n'
  printf '- Health check grace period and rolling deployment policy.\n'
  printf '- Whether MinIO/Redis remain node-local or move to managed/shared services before multi-instance scale-out.\n\n'
  printf '## Example apply steps, for a separate approved scaling change\n\n'
  printf '1. Create a launch template from approved AMI/user-data.\n'
  printf '2. Create an Auto Scaling Group across public app subnets.\n'
  printf '3. Attach ASG to `%s`.\n' "${TARGET_GROUP_ARN:-<target-group-arn>}"
  printf '4. Validate at least two healthy targets before any production DNS cutover.\n'
} > "$plan"

/bin/cat "$plan"
