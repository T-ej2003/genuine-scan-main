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
EC2_PUBLIC_IP="${EC2_PUBLIC_IP:-}"
INSTANCE_ID="${INSTANCE_ID:-}"
ENABLE_REMOTE_HOST_CHECKS="${ENABLE_REMOTE_HOST_CHECKS:-}"
SSH_USER="${SSH_USER:-ubuntu}"
SSH_HOST="${SSH_HOST:-}"
SSH_PRIVATE_KEY_FILE="${SSH_PRIVATE_KEY_FILE:-}"

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
  *) echo "TARGET_REGION_GROUP must be london, mumbai, or capetown." >&2; exit 2 ;;
esac

if [ -z "$AWS_REGION" ]; then AWS_REGION="$(expected_region "$TARGET_REGION_GROUP")"; fi
if [ -z "$EC2_PUBLIC_IP" ]; then EC2_PUBLIC_IP="$(expected_ip "$TARGET_REGION_GROUP")"; fi
if [ -z "$SSH_HOST" ]; then SSH_HOST="$EC2_PUBLIC_IP"; fi
if [ "$AWS_REGION" != "$(expected_region "$TARGET_REGION_GROUP")" ]; then
  echo "AWS_REGION $AWS_REGION does not match $TARGET_REGION_GROUP." >&2
  exit 2
fi

create_artifact_dir
out_dir="$DR_ARTIFACT_DIR/regional-capacity/$TARGET_REGION_GROUP"
/bin/mkdir -p "$out_dir"

if [ -z "$INSTANCE_ID" ]; then
  INSTANCE_ID="$(aws ec2 describe-instances \
    --region "$AWS_REGION" \
    --filters "Name=ip-address,Values=$EC2_PUBLIC_IP" \
    --query 'Reservations[].Instances[].InstanceId | [0]' \
    --output text)"
fi

if [ "$INSTANCE_ID" = "None" ] || [ -z "$INSTANCE_ID" ]; then
  echo "Could not discover EC2 instance for $TARGET_REGION_GROUP." >&2
  exit 2
fi

aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$INSTANCE_ID" --output json > "$out_dir/instance.json"
aws ec2 describe-instance-status --region "$AWS_REGION" --instance-ids "$INSTANCE_ID" --include-all-instances --output json > "$out_dir/instance-status.json"

volume_ids="$(aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[].Instances[].BlockDeviceMappings[].Ebs.VolumeId' \
  --output text)"
if [ -n "$volume_ids" ] && [ "$volume_ids" != "None" ]; then
  aws ec2 describe-volumes --region "$AWS_REGION" --volume-ids $volume_ids --output json > "$out_dir/volumes.json"
fi

start_time="$(node -e 'console.log(new Date(Date.now() - 60 * 60 * 1000).toISOString())')"
end_time="$(node -e 'console.log(new Date().toISOString())')"
aws cloudwatch get-metric-statistics \
  --region "$AWS_REGION" \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value="$INSTANCE_ID" \
  --statistics Average Maximum \
  --period 300 \
  --start-time "$start_time" \
  --end-time "$end_time" \
  --output json > "$out_dir/cloudwatch-cpu-1h.json" || true

remote_status="not-requested"
if [ "$ENABLE_REMOTE_HOST_CHECKS" = "I_APPROVE_READ_ONLY_REMOTE_HOST_CHECKS" ]; then
  if [ -n "$SSH_PRIVATE_KEY_FILE" ] && [ -f "$SSH_PRIVATE_KEY_FILE" ] && command -v ssh >/dev/null 2>&1; then
    remote_status="attempted"
    ssh -i "$SSH_PRIVATE_KEY_FILE" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$SSH_USER@$SSH_HOST" \
      'set -eu; uname -a; printf "\n== CPU ==\n"; nproc; lscpu 2>/dev/null || true; printf "\n== Memory ==\n"; free -m; printf "\n== Disk ==\n"; df -h; printf "\n== Docker ==\n"; docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || true; docker compose ps 2>/dev/null || true' \
      > "$out_dir/remote-host-evidence.log" 2>&1 || remote_status="failed"
    if [ "$remote_status" = "attempted" ]; then remote_status="captured"; fi
  else
    remote_status="missing-ssh-context"
  fi
fi

summary="$out_dir/summary.md"
instance_type="$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].InstanceType' --output text)"
{
  printf '# Regional Capacity Inventory\n\n'
  printf '%s\n' "- Target region group: \`$TARGET_REGION_GROUP\`"
  printf '%s\n' "- AWS region: \`$AWS_REGION\`"
  printf '%s\n' "- Instance ID: \`$INSTANCE_ID\`"
  printf '%s\n' "- Instance type: \`$instance_type\`"
  printf '%s\n' "- EC2 public IP: \`$EC2_PUBLIC_IP\`"
  printf '%s\n' "- Volume IDs: \`${volume_ids:-none}\`"
  printf '%s\n' "- Remote memory/disk/Docker evidence: \`$remote_status\`"
  printf '\nAWS evidence is read-only. Remote host checks run only with `ENABLE_REMOTE_HOST_CHECKS=I_APPROVE_READ_ONLY_REMOTE_HOST_CHECKS` and operator-provided SSH context.\n'
} > "$summary"

/bin/cat "$summary"
