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
CONFIRM_REGIONAL_ALB_APPLY="${CONFIRM_REGIONAL_ALB_APPLY:-}"
CONFIRM_EC2_IP_OVERRIDE="${CONFIRM_EC2_IP_OVERRIDE:-}"

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

if [ "$CONFIRM_REGIONAL_ALB_APPLY" != "I_APPROVE_REGIONAL_ALB_ENTRYPOINT_APPLY" ]; then
  echo "Refusing to apply ALB entrypoint without CONFIRM_REGIONAL_ALB_APPLY=I_APPROVE_REGIONAL_ALB_ENTRYPOINT_APPLY." >&2
  exit 2
fi

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
  echo "Refusing region mismatch: $TARGET_REGION_GROUP must use $(expected_region "$TARGET_REGION_GROUP"), got $AWS_REGION." >&2
  exit 2
fi

if [ "$EC2_PUBLIC_IP" != "$(expected_ip "$TARGET_REGION_GROUP")" ] &&
  [ "$CONFIRM_EC2_IP_OVERRIDE" != "I_APPROVE_REGIONAL_ALB_EC2_IP_OVERRIDE" ]; then
  echo "Refusing EC2 public IP mismatch for $TARGET_REGION_GROUP." >&2
  echo "Expected $(expected_ip "$TARGET_REGION_GROUP"), got $EC2_PUBLIC_IP." >&2
  exit 2
fi

ALB_NAME="${ALB_NAME:-mscqr-$TARGET_REGION_GROUP-alb}"
TARGET_GROUP_NAME="${TARGET_GROUP_NAME:-mscqr-$TARGET_REGION_GROUP-frontend-tg}"
ALB_SECURITY_GROUP_NAME="${ALB_SECURITY_GROUP_NAME:-mscqr-$TARGET_REGION_GROUP-alb-sg}"

create_artifact_dir
apply_dir="$DR_ARTIFACT_DIR/regional-alb-apply/$TARGET_REGION_GROUP"
/bin/mkdir -p "$apply_dir"
log_file="$apply_dir/apply.log"
exec > "$log_file" 2>&1

echo "Applying approved regional ALB entrypoint."
echo "Target region group: $TARGET_REGION_GROUP"
echo "AWS region: $AWS_REGION"
echo "EC2 public IP: $EC2_PUBLIC_IP"
echo "Domain names: $DOMAIN_NAME, $WWW_DOMAIN_NAME"
echo "This workflow does not perform public DNS cutover."

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
  echo "Could not discover EC2 instance/VPC from $EC2_PUBLIC_IP in $AWS_REGION." >&2
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

alb_sg_id="$(aws ec2 describe-security-groups \
  --region "$AWS_REGION" \
  --filters "Name=vpc-id,Values=$vpc_id" "Name=group-name,Values=$ALB_SECURITY_GROUP_NAME" \
  --query 'SecurityGroups[].GroupId | [0]' \
  --output text)"
if [ "$alb_sg_id" = "None" ] || [ -z "$alb_sg_id" ]; then
  alb_sg_id="$(aws ec2 create-security-group \
    --region "$AWS_REGION" \
    --group-name "$ALB_SECURITY_GROUP_NAME" \
    --description "MSCQR $TARGET_REGION_GROUP ALB entrypoint" \
    --vpc-id "$vpc_id" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Project,Value=MSCQR},{Key=Purpose,Value=DR},{Key=RegionGroup,Value=$TARGET_REGION_GROUP}]" \
    --query 'GroupId' \
    --output text)"
  echo "Created ALB security group: $alb_sg_id"
else
  echo "Reusing ALB security group: $alb_sg_id"
fi

authorize_alb_ingress() {
  port="$1"
  err_file="$apply_dir/security-group-ingress-$port.err"
  if aws ec2 authorize-security-group-ingress \
    --region "$AWS_REGION" \
    --group-id "$alb_sg_id" \
    --ip-permissions "IpProtocol=tcp,FromPort=$port,ToPort=$port,IpRanges=[{CidrIp=0.0.0.0/0,Description=MSCQR regional ALB public HTTPS entrypoint}]" \
    >/dev/null 2>"$err_file"; then
    echo "Authorized ALB security group ingress on TCP $port."
    return 0
  fi

  if /usr/bin/grep -q "InvalidPermission.Duplicate" "$err_file"; then
    echo "ALB security group ingress on TCP $port already exists."
    return 0
  fi

  /bin/cat "$err_file" >&2
  exit 1
}

for port in 80 443; do
  authorize_alb_ingress "$port"
done

target_group_arn="$(aws elbv2 describe-target-groups \
  --region "$AWS_REGION" \
  --names "$TARGET_GROUP_NAME" \
  --query 'TargetGroups[].TargetGroupArn | [0]' \
  --output text 2>/dev/null || true)"
if [ "$target_group_arn" = "None" ] || [ -z "$target_group_arn" ]; then
  target_group_arn="$(aws elbv2 create-target-group \
    --region "$AWS_REGION" \
    --name "$TARGET_GROUP_NAME" \
    --protocol HTTP \
    --port 80 \
    --vpc-id "$vpc_id" \
    --target-type instance \
    --health-check-protocol HTTP \
    --health-check-path "$HEALTH_CHECK_PATH" \
    --matcher HttpCode=200-399 \
    --tags Key=Project,Value=MSCQR Key=Purpose,Value=DR Key=RegionGroup,Value="$TARGET_REGION_GROUP" \
    --query 'TargetGroups[0].TargetGroupArn' \
    --output text)"
  echo "Created target group: $target_group_arn"
else
  echo "Reusing target group: $target_group_arn"
fi

aws elbv2 register-targets \
  --region "$AWS_REGION" \
  --target-group-arn "$target_group_arn" \
  --targets Id="$instance_id",Port=80

cert_arn="$(aws acm list-certificates \
  --region "$AWS_REGION" \
  --certificate-statuses ISSUED PENDING_VALIDATION \
  --query "CertificateSummaryList[?DomainName=='$DOMAIN_NAME'].CertificateArn | [0]" \
  --output text)"
if [ "$cert_arn" = "None" ] || [ -z "$cert_arn" ]; then
  token="$(printf '%s-%s' "$TARGET_REGION_GROUP" "$DOMAIN_NAME" | /usr/bin/tr -cd '[:alnum:]-' | /usr/bin/cut -c1-32)"
  cert_arn="$(aws acm request-certificate \
    --region "$AWS_REGION" \
    --domain-name "$DOMAIN_NAME" \
    --subject-alternative-names "$WWW_DOMAIN_NAME" \
    --validation-method DNS \
    --idempotency-token "$token" \
    --tags Key=Project,Value=MSCQR Key=Purpose,Value=DR Key=RegionGroup,Value="$TARGET_REGION_GROUP" \
    --query CertificateArn \
    --output text)"
  echo "Requested ACM certificate: $cert_arn"
else
  echo "Reusing ACM certificate: $cert_arn"
fi

aws acm describe-certificate --region "$AWS_REGION" --certificate-arn "$cert_arn" --output json > "$apply_dir/certificate.json"

node --input-type=module - "$apply_dir/certificate.json" "$apply_dir/acm-validation-change-batch.json" <<'NODE'
import fs from "node:fs";
const [input, output] = process.argv.slice(2);
const certificate = JSON.parse(fs.readFileSync(input, "utf8")).Certificate;
const changes = [];
for (const option of certificate.DomainValidationOptions || []) {
  const record = option.ResourceRecord;
  if (!record?.Name || !record?.Type || !record?.Value) continue;
  changes.push({
    Action: "UPSERT",
    ResourceRecordSet: {
      Name: record.Name,
      Type: record.Type,
      TTL: 300,
      ResourceRecords: [{ Value: record.Value }],
    },
  });
}
fs.writeFileSync(output, JSON.stringify({ Comment: "MSCQR DR regional ALB ACM DNS validation", Changes: changes }, null, 2));
NODE

validation_count="$(node --input-type=module - "$apply_dir/acm-validation-change-batch.json" <<'NODE'
import fs from "node:fs";
const batch = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
console.log(batch.Changes.length);
NODE
)"
if [ "$validation_count" -gt 0 ]; then
  aws route53 change-resource-record-sets \
    --hosted-zone-id "$HOSTED_ZONE_ID" \
    --change-batch "file://$apply_dir/acm-validation-change-batch.json" \
    --output json > "$apply_dir/acm-validation-change.json"
  echo "UPSERTED ACM DNS validation records in hosted zone $HOSTED_ZONE_ID."
else
  echo "No ACM validation records found to UPSERT."
fi

cert_status="$(aws acm describe-certificate --region "$AWS_REGION" --certificate-arn "$cert_arn" --query 'Certificate.Status' --output text)"
attempts=0
while [ "$cert_status" != "ISSUED" ] && [ "$attempts" -lt 30 ]; do
  attempts=$((attempts + 1))
  echo "Waiting for ACM certificate validation: attempt $attempts/30, current status $cert_status"
  /bin/sleep 20
  cert_status="$(aws acm describe-certificate --region "$AWS_REGION" --certificate-arn "$cert_arn" --query 'Certificate.Status' --output text)"
done

if [ "$cert_status" != "ISSUED" ]; then
  echo "ACM certificate is not ISSUED yet. Re-run after DNS validation completes." >&2
  exit 3
fi

alb_arn="$(aws elbv2 describe-load-balancers \
  --region "$AWS_REGION" \
  --names "$ALB_NAME" \
  --query 'LoadBalancers[].LoadBalancerArn | [0]' \
  --output text 2>/dev/null || true)"
if [ "$alb_arn" = "None" ] || [ -z "$alb_arn" ]; then
  alb_arn="$(aws elbv2 create-load-balancer \
    --region "$AWS_REGION" \
    --name "$ALB_NAME" \
    --subnets $subnet_ids \
    --security-groups "$alb_sg_id" \
    --scheme internet-facing \
    --type application \
    --ip-address-type ipv4 \
    --tags Key=Project,Value=MSCQR Key=Purpose,Value=DR Key=RegionGroup,Value="$TARGET_REGION_GROUP" \
    --query 'LoadBalancers[0].LoadBalancerArn' \
    --output text)"
  echo "Created ALB: $alb_arn"
else
  echo "Reusing ALB: $alb_arn"
fi

alb_dns_name="$(aws elbv2 describe-load-balancers --region "$AWS_REGION" --load-balancer-arns "$alb_arn" --query 'LoadBalancers[0].DNSName' --output text)"
alb_zone_id="$(aws elbv2 describe-load-balancers --region "$AWS_REGION" --load-balancer-arns "$alb_arn" --query 'LoadBalancers[0].CanonicalHostedZoneId' --output text)"

http_listener_arn="$(aws elbv2 describe-listeners \
  --region "$AWS_REGION" \
  --load-balancer-arn "$alb_arn" \
  --query 'Listeners[?Port==`80`].ListenerArn | [0]' \
  --output text)"
if [ "$http_listener_arn" = "None" ] || [ -z "$http_listener_arn" ]; then
  aws elbv2 create-listener \
    --region "$AWS_REGION" \
    --load-balancer-arn "$alb_arn" \
    --protocol HTTP \
    --port 80 \
    --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}' \
    --output json > "$apply_dir/http-listener.json"
else
  aws elbv2 modify-listener \
    --region "$AWS_REGION" \
    --listener-arn "$http_listener_arn" \
    --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}' \
    --output json > "$apply_dir/http-listener.json"
fi

https_listener_arn="$(aws elbv2 describe-listeners \
  --region "$AWS_REGION" \
  --load-balancer-arn "$alb_arn" \
  --query 'Listeners[?Port==`443`].ListenerArn | [0]' \
  --output text)"
if [ "$https_listener_arn" = "None" ] || [ -z "$https_listener_arn" ]; then
  aws elbv2 create-listener \
    --region "$AWS_REGION" \
    --load-balancer-arn "$alb_arn" \
    --protocol HTTPS \
    --port 443 \
    --certificates CertificateArn="$cert_arn" \
    --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 \
    --default-actions Type=forward,TargetGroupArn="$target_group_arn" \
    --output json > "$apply_dir/https-listener.json"
else
  aws elbv2 modify-listener \
    --region "$AWS_REGION" \
    --listener-arn "$https_listener_arn" \
    --certificates CertificateArn="$cert_arn" \
    --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 \
    --default-actions Type=forward,TargetGroupArn="$target_group_arn" \
    --output json > "$apply_dir/https-listener.json"
fi

aws elbv2 describe-target-health \
  --region "$AWS_REGION" \
  --target-group-arn "$target_group_arn" \
  --output json > "$apply_dir/target-health.json"

{
  printf 'TARGET_REGION_GROUP=%s\n' "$TARGET_REGION_GROUP"
  printf 'AWS_REGION=%s\n' "$AWS_REGION"
  printf 'ALB_ARN=%s\n' "$alb_arn"
  printf 'ALB_DNS_NAME=%s\n' "$alb_dns_name"
  printf 'ALB_HOSTED_ZONE_ID=%s\n' "$alb_zone_id"
  printf 'TARGET_GROUP_ARN=%s\n' "$target_group_arn"
  printf 'ACM_CERTIFICATE_ARN=%s\n' "$cert_arn"
  printf 'INSTANCE_ID=%s\n' "$instance_id"
} > "$apply_dir/outputs.env"

echo "Regional ALB entrypoint apply completed."
echo "ALB DNS name: $alb_dns_name"
echo "ALB hosted zone ID: $alb_zone_id"
echo "Evidence directory: $apply_dir"
