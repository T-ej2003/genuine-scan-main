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
DOMAIN_NAME="${DOMAIN_NAME:-mscqr.com}"
WWW_DOMAIN_NAME="${WWW_DOMAIN_NAME:-www.mscqr.com}"
HOSTED_ZONE_ID="${HOSTED_ZONE_ID:-Z0569586VLFIGGVI7HAZ}"
HEALTH_CHECK_PATH="${HEALTH_CHECK_PATH:-/healthz}"

expected_region() {
  case "$1" in
    london) printf '%s\n' "eu-west-2" ;;
    mumbai) printf '%s\n' "ap-south-1" ;;
    capetown) printf '%s\n' "af-south-1" ;;
    *) return 1 ;;
  esac
}

expected_ip() {
  case "$1" in
    london) printf '%s\n' "13.135.108.69" ;;
    mumbai) printf '%s\n' "15.206.45.108" ;;
    capetown) printf '%s\n' "15.240.28.113" ;;
    *) return 1 ;;
  esac
}

case "$TARGET_REGION_GROUP" in
  london|mumbai|capetown) ;;
  *)
    echo "TARGET_REGION_GROUP must be one of: london, mumbai, capetown." >&2
    exit 2
    ;;
esac

if [ -z "$AWS_REGION" ]; then
  AWS_REGION="$(expected_region "$TARGET_REGION_GROUP")"
fi
if [ -z "$EC2_PUBLIC_IP" ]; then
  EC2_PUBLIC_IP="$(expected_ip "$TARGET_REGION_GROUP")"
fi

if [ "$AWS_REGION" != "$(expected_region "$TARGET_REGION_GROUP")" ]; then
  echo "AWS_REGION $AWS_REGION does not match $TARGET_REGION_GROUP." >&2
  exit 2
fi

ALB_NAME="${ALB_NAME:-mscqr-$TARGET_REGION_GROUP-alb}"
TARGET_GROUP_NAME="${TARGET_GROUP_NAME:-mscqr-$TARGET_REGION_GROUP-frontend-tg}"
ALB_SECURITY_GROUP_NAME="${ALB_SECURITY_GROUP_NAME:-mscqr-$TARGET_REGION_GROUP-alb-sg}"

create_artifact_dir
plan_dir="$DR_ARTIFACT_DIR/alb-plan/$TARGET_REGION_GROUP"
/bin/mkdir -p "$plan_dir"

instance_id="$(aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --filters "Name=ip-address,Values=$EC2_PUBLIC_IP" \
  --query 'Reservations[].Instances[].InstanceId | [0]' \
  --output text)"
vpc_id="$(aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --filters "Name=ip-address,Values=$EC2_PUBLIC_IP" \
  --query 'Reservations[].Instances[].VpcId | [0]' \
  --output text)"

if [ "$instance_id" = "None" ] || [ -z "$instance_id" ] || [ "$vpc_id" = "None" ] || [ -z "$vpc_id" ]; then
  echo "Could not discover EC2 instance/VPC from EC2_PUBLIC_IP=$EC2_PUBLIC_IP in $AWS_REGION." >&2
  exit 2
fi

subnet_ids="$(aws ec2 describe-subnets \
  --region "$AWS_REGION" \
  --filters "Name=vpc-id,Values=$vpc_id" \
  --query 'Subnets[?MapPublicIpOnLaunch==`true`].SubnetId' \
  --output text)"
if [ -z "$subnet_ids" ] || [ "$subnet_ids" = "None" ]; then
  subnet_ids="$(aws ec2 describe-subnets \
    --region "$AWS_REGION" \
    --filters "Name=vpc-id,Values=$vpc_id" \
    --query 'Subnets[].SubnetId' \
    --output text)"
fi

set -- $subnet_ids
if [ "$#" -lt 2 ]; then
  echo "ALB requires at least two subnets in $vpc_id; discovered: $subnet_ids" >&2
  exit 2
fi

security_groups="$(aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --filters "Name=ip-address,Values=$EC2_PUBLIC_IP" \
  --query 'Reservations[].Instances[].SecurityGroups[].GroupId' \
  --output text)"

plan_json="$plan_dir/plan.json"
plan_md="$plan_dir/plan.md"

{
  printf '{\n'
  printf '  "targetRegionGroup": "%s",\n' "$(json_escape "$TARGET_REGION_GROUP")"
  printf '  "awsRegion": "%s",\n' "$(json_escape "$AWS_REGION")"
  printf '  "domainName": "%s",\n' "$(json_escape "$DOMAIN_NAME")"
  printf '  "wwwDomainName": "%s",\n' "$(json_escape "$WWW_DOMAIN_NAME")"
  printf '  "hostedZoneId": "%s",\n' "$(json_escape "$HOSTED_ZONE_ID")"
  printf '  "ec2PublicIp": "%s",\n' "$(json_escape "$EC2_PUBLIC_IP")"
  printf '  "instanceId": "%s",\n' "$(json_escape "$instance_id")"
  printf '  "vpcId": "%s",\n' "$(json_escape "$vpc_id")"
  printf '  "subnetIds": "%s",\n' "$(json_escape "$subnet_ids")"
  printf '  "instanceSecurityGroupIds": "%s",\n' "$(json_escape "$security_groups")"
  printf '  "albName": "%s",\n' "$(json_escape "$ALB_NAME")"
  printf '  "targetGroupName": "%s",\n' "$(json_escape "$TARGET_GROUP_NAME")"
  printf '  "albSecurityGroupName": "%s",\n' "$(json_escape "$ALB_SECURITY_GROUP_NAME")"
  printf '  "healthCheckPath": "%s"\n' "$(json_escape "$HEALTH_CHECK_PATH")"
  printf '}\n'
} > "$plan_json"

{
  printf '# Regional ALB/ACM entrypoint plan\n\n'
  printf '%s\n' "- Target region group: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- AWS region: \`$AWS_REGION\`"
  printf '%s\n' "- EC2 public IP: \`$EC2_PUBLIC_IP\`"
  printf '%s\n' "- Instance target: \`$instance_id\` on HTTP port 80"
  printf '%s\n' "- VPC: \`$vpc_id\`"
  printf '%s\n' "- Candidate ALB subnets: \`$subnet_ids\`"
  printf '%s\n' "- Existing instance security groups: \`$security_groups\`"
  printf '%s\n' "- ALB name: \`$ALB_NAME\`"
  printf '%s\n' "- Target group: \`$TARGET_GROUP_NAME\`"
  printf '%s\n' "- ALB security group: \`$ALB_SECURITY_GROUP_NAME\`"
  printf '%s\n\n' "- Health check path: \`$HEALTH_CHECK_PATH\`"
  printf '## Planned changes\n\n'
  printf '1. Create or reuse an internet-facing Application Load Balancer in `%s`.\n' "$AWS_REGION"
  printf '2. Create or reuse `%s` allowing inbound TCP 80/443 from the public internet.\n' "$ALB_SECURITY_GROUP_NAME"
  printf '3. Create or reuse target group `%s` and register instance `%s` on port 80.\n' "$TARGET_GROUP_NAME" "$instance_id"
  printf '4. Request or reuse a regional ACM certificate for `%s` and `%s`.\n' "$DOMAIN_NAME" "$WWW_DOMAIN_NAME"
  printf '5. Create DNS validation CNAME records in hosted zone `%s` for ACM only.\n' "$HOSTED_ZONE_ID"
  printf '6. Create HTTP listener 80 redirecting to HTTPS 443.\n'
  printf '7. Create HTTPS listener 443 forwarding to the target group after ACM is issued.\n'
  printf '8. Generate Route 53 ALB alias cutover JSON separately. Do not cut over DNS from this plan.\n\n'
  printf '## Manual apply command\n\n'
  printf '```sh\n'
  printf 'TARGET_REGION_GROUP=%s AWS_REGION=%s EC2_PUBLIC_IP=%s CONFIRM_REGIONAL_ALB_APPLY=I_APPROVE_REGIONAL_ALB_ENTRYPOINT_APPLY scripts/dr/apply-regional-alb-entrypoint-approved.sh\n' "$TARGET_REGION_GROUP" "$AWS_REGION" "$EC2_PUBLIC_IP"
  printf '```\n'
} > "$plan_md"

/bin/cat "$plan_md"
printf '\nPlan JSON: %s\n' "$plan_json"
