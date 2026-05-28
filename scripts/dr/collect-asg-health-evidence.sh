#!/bin/sh
set -eu

usage() {
  cat <<'USAGE'
Usage: scripts/dr/collect-asg-health-evidence.sh

Read-only evidence collector for regional ASG health disagreements.

Required environment:
  TARGET_REGION_GROUP  mumbai or capetown
  AWS_REGION           AWS region, for example ap-south-1
  ASG_NAME             Auto Scaling Group name
  TARGET_GROUP_ARN     ALB target group ARN

Optional read-only SSH inspection:
  ENABLE_ASG_SSH_DEEP_INSPECTION=I_APPROVE_READ_ONLY_SSH
  ASG_SSH_KEY=/path/to/key.pem
  ASG_SSH_USER=ubuntu

Evidence is written under /tmp/mscqr-asg-evidence and gzipped.
This script does not mutate AWS resources.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

TARGET_REGION_GROUP="${TARGET_REGION_GROUP:-}"
AWS_REGION="${AWS_REGION:-}"
ASG_NAME="${ASG_NAME:-}"
TARGET_GROUP_ARN="${TARGET_GROUP_ARN:-}"
ASG_SSH_USER="${ASG_SSH_USER:-ubuntu}"
ASG_SSH_KEY="${ASG_SSH_KEY:-}"
ENABLE_ASG_SSH_DEEP_INSPECTION="${ENABLE_ASG_SSH_DEEP_INSPECTION:-}"

[ -n "$TARGET_REGION_GROUP" ] || { echo "TARGET_REGION_GROUP is required." >&2; exit 1; }
[ -n "$AWS_REGION" ] || { echo "AWS_REGION is required." >&2; exit 1; }
[ -n "$ASG_NAME" ] || { echo "ASG_NAME is required." >&2; exit 1; }
[ -n "$TARGET_GROUP_ARN" ] || { echo "TARGET_GROUP_ARN is required." >&2; exit 1; }
command -v aws >/dev/null 2>&1 || { echo "aws CLI is required." >&2; exit 1; }

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
out_dir="/tmp/mscqr-asg-evidence"
mkdir -p "$out_dir"
log_file="$out_dir/${TARGET_REGION_GROUP}-asg-health-evidence-${timestamp}.log"

run_section() {
  title="$1"
  shift
  {
    printf '\n########################################################################\n'
    printf '=== %s ===\n' "$title"
    printf '########################################################################\n'
    "$@" 2>&1 || printf 'section failed: %s\n' "$title"
  } >> "$log_file"
}

safe_console_output() {
  instance_id="$1"
  aws ec2 get-console-output \
    --region "$AWS_REGION" \
    --instance-id "$instance_id" \
    --latest \
    --output text |
    grep -E 'MSCQR ASG bootstrap|cloud-init|Container genuine-scan|Waiting for|CONDITIONALLY_READY|ASG web-node|ERROR:|docker compose|Docker|Node|npm|aws cli|git|healthz|health/ready|Target|Started|Healthy|failed|Failed|diagnostics|nginx|listener|backend readiness|frontend' || true
}

collect_instance_ips() {
  instance_id="$1"
  aws ec2 describe-instances \
    --region "$AWS_REGION" \
    --instance-ids "$instance_id" \
    --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,LaunchTime:LaunchTime,PrivateIp:PrivateIpAddress,PublicIp:PublicIpAddress}' \
    --output table
}

ssh_deep_inspection() {
  instance_id="$1"
  public_ip="$2"
  if [ "$ENABLE_ASG_SSH_DEEP_INSPECTION" != "I_APPROVE_READ_ONLY_SSH" ]; then
    printf 'SSH deep inspection skipped for %s: approval env not set.\n' "$instance_id"
    return 0
  fi
  if [ -z "$ASG_SSH_KEY" ] || [ ! -f "$ASG_SSH_KEY" ]; then
    printf 'SSH deep inspection skipped for %s: ASG_SSH_KEY missing or not a file.\n' "$instance_id"
    return 0
  fi
  if [ -z "$public_ip" ] || [ "$public_ip" = "None" ]; then
    printf 'SSH deep inspection skipped for %s: no public IP.\n' "$instance_id"
    return 0
  fi

  ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -i "$ASG_SSH_KEY" "$ASG_SSH_USER@$public_ip" '
    set -eu
    printf "remote instance: %s\n" "$(hostname)"
    printf "\n--- cloud-init bootstrap tail ---\n"
    sudo tail -n 220 /var/log/mscqr-asg-bootstrap.log 2>/dev/null || true
    printf "\n--- cloud-init output tail ---\n"
    sudo tail -n 180 /var/log/cloud-init-output.log 2>/dev/null || true
    printf "\n--- host listeners ---\n"
    (ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || true) | awk "NR == 1 || /:80|:443|:4000/"
    printf "\n--- docker ps ---\n"
    docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || true
    printf "\n--- local /healthz ---\n"
    curl -sS -m 8 -o /tmp/mscqr-healthz.body -w "http_status=%{http_code} total_time=%{time_total}\n" http://127.0.0.1/healthz 2>&1 || true
    head -n 8 /tmp/mscqr-healthz.body 2>/dev/null || true
    printf "\n--- local /api/health/ready ---\n"
    curl -sS -m 8 -o /tmp/mscqr-ready.body -w "http_status=%{http_code} total_time=%{time_total}\n" http://127.0.0.1/api/health/ready 2>&1 || true
    node -e "const fs=require(\"fs\"); const p=\"/tmp/mscqr-ready.body\"; if (fs.existsSync(p)) { try { const x=JSON.parse(fs.readFileSync(p,\"utf8\")); const d=x.dependencies||{}; console.log(JSON.stringify({success:x.success===true,status:x.status||\"unknown\",dependencies:Object.fromEntries([\"database\",\"redis\",\"objectStorage\"].map(k=>[k,{configured:d[k]?.configured===true,ready:d[k]?.ready===true,errorPresent:Boolean(d[k]?.error)}]))})); } catch { console.log(fs.readFileSync(p,\"utf8\").slice(0,500)); } }" 2>/dev/null || true
    printf "\n--- backend logs tail ---\n"
    docker logs genuine-scan-backend --tail 120 2>&1 || true
    printf "\n--- frontend logs tail ---\n"
    docker logs genuine-scan-frontend --tail 120 2>&1 || true
  ' 2>&1 || printf 'SSH deep inspection failed for %s (%s).\n' "$instance_id" "$public_ip"
}

{
  printf '=== Evidence started UTC ===\n'
  date -u
  printf '\nTARGET_REGION_GROUP=%s\nAWS_REGION=%s\nASG_NAME=%s\nTARGET_GROUP_ARN=%s\n' "$TARGET_REGION_GROUP" "$AWS_REGION" "$ASG_NAME" "$TARGET_GROUP_ARN"
  printf '\n=== Current commit ===\n'
  git log --oneline -5 2>/dev/null || true
} > "$log_file"

run_section "ASG" aws autoscaling describe-auto-scaling-groups \
  --region "$AWS_REGION" \
  --auto-scaling-group-names "$ASG_NAME" \
  --query 'AutoScalingGroups[0].{Name:AutoScalingGroupName,Min:MinSize,Desired:DesiredCapacity,Max:MaxSize,LaunchTemplate:LaunchTemplate,Instances:Instances[].{Id:InstanceId,Lifecycle:LifecycleState,Health:HealthStatus,AZ:AvailabilityZone}}' \
  --output json

run_section "Target health" aws elbv2 describe-target-health \
  --region "$AWS_REGION" \
  --target-group-arn "$TARGET_GROUP_ARN" \
  --output table

ASG_INSTANCE_IDS="$(aws autoscaling describe-auto-scaling-groups \
  --region "$AWS_REGION" \
  --auto-scaling-group-names "$ASG_NAME" \
  --query 'AutoScalingGroups[0].Instances[].InstanceId' \
  --output text | tr '\t' '\n')"

{
  printf '\n=== Current ASG instance IDs ===\n'
  printf '%s\n' "$ASG_INSTANCE_IDS"
} >> "$log_file"

for instance_id in $ASG_INSTANCE_IDS; do
  [ -n "$instance_id" ] || continue
  run_section "Instance $instance_id IPs" collect_instance_ips "$instance_id"
  run_section "Instance $instance_id filtered console output" safe_console_output "$instance_id"
  public_ip="$(aws ec2 describe-instances \
    --region "$AWS_REGION" \
    --instance-ids "$instance_id" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text 2>/dev/null || true)"
  run_section "Instance $instance_id optional SSH deep inspection" ssh_deep_inspection "$instance_id" "$public_ip"
done

gzip -kf "$log_file"

printf 'Evidence log: %s\n' "$log_file"
printf 'Gzipped evidence log: %s.gz\n' "$log_file"
