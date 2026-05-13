#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=scripts/dr/common.sh
. "$SCRIPT_DIR/common.sh"

require_repo_root
require_command aws

TARGET_REGION_GROUP="${TARGET_REGION_GROUP:-${1:-}}"
AWS_REGION="${AWS_REGION:-}"
DOMAIN_NAME="${DOMAIN_NAME:-mscqr.com}"
WWW_DOMAIN_NAME="${WWW_DOMAIN_NAME:-www.mscqr.com}"
EC2_PUBLIC_IP="${EC2_PUBLIC_IP:-}"
SOURCE_LABEL="MSCQR regional ALB inventory"

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

aws_json() {
  output_file="$1"
  shift
  set +e
  "$@" --output json > "$output_file" 2>"$output_file.stderr"
  status="$?"
  set -e
  if [ "$status" -ne 0 ]; then
    printf '{"error":"command failed","command":"%s"}\n' "$(json_escape "$*")" > "$output_file"
    /bin/cat "$output_file.stderr" >> "$DR_ARTIFACT_DIR/alb-inventory/$TARGET_REGION_GROUP/errors.log"
  fi
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

expected="$(expected_region "$TARGET_REGION_GROUP")"
if [ "$AWS_REGION" != "$expected" ]; then
  echo "AWS_REGION $AWS_REGION does not match $TARGET_REGION_GROUP expected region $expected." >&2
  exit 2
fi

if [ -z "$EC2_PUBLIC_IP" ]; then
  EC2_PUBLIC_IP="$(expected_ip "$TARGET_REGION_GROUP")"
fi

create_artifact_dir
inventory_dir="$DR_ARTIFACT_DIR/alb-inventory/$TARGET_REGION_GROUP"
/bin/mkdir -p "$inventory_dir"
: > "$inventory_dir/errors.log"

aws_json "$inventory_dir/instances-by-public-ip.json" \
  aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --filters "Name=ip-address,Values=$EC2_PUBLIC_IP"

instance_id="$(aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --filters "Name=ip-address,Values=$EC2_PUBLIC_IP" \
  --query 'Reservations[].Instances[].InstanceId | [0]' \
  --output text 2>/dev/null || true)"

vpc_id="$(aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --filters "Name=ip-address,Values=$EC2_PUBLIC_IP" \
  --query 'Reservations[].Instances[].VpcId | [0]' \
  --output text 2>/dev/null || true)"

if [ "$instance_id" = "None" ]; then instance_id=""; fi
if [ "$vpc_id" = "None" ]; then vpc_id=""; fi

aws_json "$inventory_dir/vpcs.json" aws ec2 describe-vpcs --region "$AWS_REGION"

if [ -n "$vpc_id" ]; then
  aws_json "$inventory_dir/subnets.json" aws ec2 describe-subnets --region "$AWS_REGION" --filters "Name=vpc-id,Values=$vpc_id"
  aws_json "$inventory_dir/security-groups.json" aws ec2 describe-security-groups --region "$AWS_REGION" --filters "Name=vpc-id,Values=$vpc_id"
else
  aws_json "$inventory_dir/subnets.json" aws ec2 describe-subnets --region "$AWS_REGION"
  aws_json "$inventory_dir/security-groups.json" aws ec2 describe-security-groups --region "$AWS_REGION"
fi

aws_json "$inventory_dir/load-balancers.json" aws elbv2 describe-load-balancers --region "$AWS_REGION"
aws_json "$inventory_dir/target-groups.json" aws elbv2 describe-target-groups --region "$AWS_REGION"
aws_json "$inventory_dir/certificates.json" aws acm list-certificates --region "$AWS_REGION" --certificate-statuses ISSUED PENDING_VALIDATION

lb_arns="$(aws elbv2 describe-load-balancers \
  --region "$AWS_REGION" \
  --query 'LoadBalancers[].LoadBalancerArn' \
  --output text 2>/dev/null || true)"

: > "$inventory_dir/listeners.jsonl"
for lb_arn in $lb_arns; do
  aws elbv2 describe-listeners --region "$AWS_REGION" --load-balancer-arn "$lb_arn" --output json >> "$inventory_dir/listeners.jsonl" 2>>"$inventory_dir/errors.log" || true
done

latest_cert_arn="$(aws acm list-certificates \
  --region "$AWS_REGION" \
  --certificate-statuses ISSUED PENDING_VALIDATION \
  --query "CertificateSummaryList[?DomainName=='$DOMAIN_NAME'].CertificateArn | [0]" \
  --output text 2>/dev/null || true)"
if [ "$latest_cert_arn" != "None" ] && [ -n "$latest_cert_arn" ]; then
  aws_json "$inventory_dir/domain-certificate.json" aws acm describe-certificate --region "$AWS_REGION" --certificate-arn "$latest_cert_arn"
else
  printf '{"certificateArn":null}\n' > "$inventory_dir/domain-certificate.json"
fi

summary="$DR_ARTIFACT_DIR/alb-inventory/$TARGET_REGION_GROUP-summary.md"
{
  printf '# %s\n\n' "$SOURCE_LABEL"
  printf '%s\n' "- Target region group: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- AWS region: \`$AWS_REGION\`"
  printf '%s\n' "- Domain: \`$DOMAIN_NAME\`"
  printf '%s\n' "- WWW domain: \`$WWW_DOMAIN_NAME\`"
  printf '%s\n' "- EC2 public IP: \`$EC2_PUBLIC_IP\`"
  if [ -n "$instance_id" ]; then
    printf '%s\n' "- Discovered instance: \`$instance_id\`"
  else
    printf '%s\n' '- Discovered instance: not found from public IP'
  fi
  if [ -n "$vpc_id" ]; then
    printf '%s\n' "- Discovered VPC: \`$vpc_id\`"
  else
    printf '%s\n' '- Discovered VPC: not found from public IP'
  fi
  if [ "$latest_cert_arn" != "None" ] && [ -n "$latest_cert_arn" ]; then
    printf '%s\n' "- Existing ACM certificate candidate: \`$latest_cert_arn\`"
  else
    printf '%s\n' '- Existing ACM certificate candidate: not found'
  fi
  printf '\nEvidence directory: `%s`\n' "$inventory_dir"
  printf '\nThis script is read-only and does not mutate AWS resources.\n'
} > "$summary"

/bin/cat "$summary"
