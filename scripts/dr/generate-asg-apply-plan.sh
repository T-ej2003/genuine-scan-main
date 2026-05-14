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
MIN_SIZE="${MIN_SIZE:-2}"
DESIRED_CAPACITY="${DESIRED_CAPACITY:-2}"
MAX_SIZE="${MAX_SIZE:-4}"

case "$TARGET_REGION_GROUP" in
  mumbai|capetown) ;;
  *) echo "TARGET_REGION_GROUP must be mumbai or capetown." >&2; exit 2 ;;
esac

case "$TARGET_REGION_GROUP:$AWS_REGION" in
  mumbai:ap-south-1|capetown:af-south-1) ;;
  *) echo "AWS_REGION does not match TARGET_REGION_GROUP." >&2; exit 2 ;;
esac

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

/bin/cat > "$out_dir/proposed-launch-template.json" <<JSON
{
  "LaunchTemplateName": "$launch_template_name",
  "LaunchTemplateData": {
    "ImageId": "$SOURCE_AMI",
    "InstanceType": "$SOURCE_INSTANCE_TYPE",
    "SecurityGroupIds": ["$SOURCE_SECURITY_GROUP"],
    "MetadataOptions": {
      "HttpTokens": "required",
      "HttpEndpoint": "enabled"
    },
    "TagSpecifications": [
      {
        "ResourceType": "instance",
        "Tags": [
          { "Key": "Project", "Value": "MSCQR" },
          { "Key": "Purpose", "Value": "DR" },
          { "Key": "RegionGroup", "Value": "$TARGET_REGION_GROUP" }
        ]
      }
    ]
  }
}
JSON

/bin/cat > "$out_dir/proposed-asg.json" <<JSON
{
  "AutoScalingGroupName": "$asg_name",
  "LaunchTemplateName": "$launch_template_name",
  "MinSize": $MIN_SIZE,
  "DesiredCapacity": $DESIRED_CAPACITY,
  "MaxSize": $MAX_SIZE,
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
  printf '%s\n' "- Selected app subnets: \`$selected_subnet_ids\`"
  printf '%s\n' "- Proposed ASG capacity: \`min=$MIN_SIZE desired=$DESIRED_CAPACITY max=$MAX_SIZE\`"
  printf '\nRisks to review before ASG apply: node-local Redis, MinIO, app secrets, migrations, sessions, filesystem state, background workers, and sticky behavior.\n'
} > "$out_dir/asg-apply-plan.md"

/bin/cat "$out_dir/asg-apply-plan.md"
