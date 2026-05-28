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
  ALLOW_SSH_DEEP_INSPECTION=true
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
ALLOW_SSH_DEEP_INSPECTION="${ALLOW_SSH_DEEP_INSPECTION:-}"
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
    --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,LaunchTime:LaunchTime,PrivateIp:PrivateIpAddress,PublicIp:PublicIpAddress,Subnet:SubnetId,SecurityGroups:SecurityGroups[].GroupId}' \
    --output table
}

collect_all_instance_ips() {
  [ "$#" -gt 0 ] || {
    printf 'No current ASG instance IDs to describe.\n'
    return 0
  }
  aws ec2 describe-instances \
    --region "$AWS_REGION" \
    --instance-ids "$@" \
    --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,LaunchTime:LaunchTime,PrivateIp:PrivateIpAddress,PublicIp:PublicIpAddress,SecurityGroups:SecurityGroups[].GroupId}' \
    --output table
}

get_instance_public_ip() {
  instance_id="$1"
  aws ec2 describe-instances \
    --region "$AWS_REGION" \
    --instance-ids "$instance_id" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text 2>/dev/null || true
}

collect_instance_target_health() {
  instance_id="$1"
  node -e 'const fs=require("fs"); const target=process.argv[2]; const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); const d=(p.TargetHealthDescriptions||[]).find((item)=>item.Target?.Id===target); if (!d) { console.log(`${target}: target_health=not_registered reason=Target.NotRegistered`); process.exit(0); } console.log(`${target}: target_health=${d.TargetHealth?.State||"unknown"} reason=${d.TargetHealth?.Reason||""} port=${d.Target?.Port||""}`);' "$target_health_json" "$instance_id"
}

curl_public_health() {
  instance_id="$1"
  public_ip="$2"
  if [ -z "$public_ip" ] || [ "$public_ip" = "None" ]; then
    printf 'Public /healthz curl skipped for %s: no public IP.\n' "$instance_id"
    return 0
  fi
  body_path="$out_dir/public-healthz-$instance_id.body"
  meta_path="$out_dir/public-healthz-$instance_id.meta"
  if curl -sS -m 10 -o "$body_path" -w 'http_status=%{http_code} total_time=%{time_total} remote_ip=%{remote_ip}\n' "http://$public_ip/healthz" > "$meta_path" 2>&1; then
    printf 'Public /healthz curl for %s (%s): ok ' "$instance_id" "$public_ip"
  else
    printf 'Public /healthz curl for %s (%s): failed ' "$instance_id" "$public_ip"
  fi
  cat "$meta_path" 2>/dev/null || true
  printf 'Public /healthz body snippet for %s:\n' "$instance_id"
  sed -n '1,8p' "$body_path" 2>/dev/null | tr -cd '\11\12\15\40-\176' || true
  printf '\n'
}

print_asg_target_health_summary() {
  /bin/cat "$target_summary_env" 2>/dev/null || true
  node -e 'const fs=require("fs"); const asg=JSON.parse(fs.readFileSync(process.argv[1],"utf8")).AutoScalingGroups?.[0] || {}; const summary=JSON.parse(fs.readFileSync(process.argv[2],"utf8")); const instances=asg.Instances||[]; const lifecycle=instances.map((i)=>`${i.InstanceId}:${i.LifecycleState || "unknown"}:${i.HealthStatus || "unknown"}`).join(",") || "none"; const churn=instances.some((i)=>i.LifecycleState!=="InService" || i.HealthStatus!=="Healthy") || !summary.ready; console.log(`ASG_LIFECYCLE_HEALTH=${lifecycle}`); console.log(`LEGACY_SOURCE_TARGET_STILL_REGISTERED=${summary.legacyOrNonAsgHealthyTargetIds.length > 0 ? "true" : "false"}`); console.log(`ASG_READINESS_USES_CURRENT_ASG_TARGETS_ONLY=true`); console.log(`POSSIBLE_ASG_HEALTH_REPLACEMENT_BEFORE_TARGET_STABILIZES=${churn ? "true" : "false"}`);' "$asg_json" "$target_summary_json" 2>/dev/null || true
}

ssh_deep_inspection() {
  instance_id="$1"
  public_ip="$2"
  if [ "$ALLOW_SSH_DEEP_INSPECTION" != "true" ] && [ "$ENABLE_ASG_SSH_DEEP_INSPECTION" != "I_APPROVE_READ_ONLY_SSH" ]; then
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
    printf "\n--- docker port frontend ---\n"
    docker port genuine-scan-frontend 2>/dev/null || true
    printf "\n--- firewall summary ---\n"
    (sudo iptables -S 2>/dev/null | head -n 80 || true)
    (sudo nft list ruleset 2>/dev/null | head -n 120 || true)
    printf "\n--- docker ps ---\n"
    docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || true
    printf "\n--- local /healthz ---\n"
    curl -sS -m 8 -o /tmp/mscqr-healthz.body -w "http_status=%{http_code} total_time=%{time_total}\n" http://127.0.0.1/healthz 2>&1 || true
    head -n 8 /tmp/mscqr-healthz.body 2>/dev/null || true
    printf "\n--- localhost /healthz ---\n"
    curl -sS -m 8 -o /tmp/mscqr-localhost-healthz.body -w "http_status=%{http_code} total_time=%{time_total}\n" http://localhost/healthz 2>&1 || true
    head -n 8 /tmp/mscqr-localhost-healthz.body 2>/dev/null || true
    host_ip="$(ip route get 1.1.1.1 2>/dev/null | awk "{for (i = 1; i <= NF; i++) if (\$i == \"src\") {print \$(i + 1); exit}}" || true)"
    if [ -z "$host_ip" ]; then
      host_ip="$(hostname -I 2>/dev/null | awk "{print \$1}")"
    fi
    if [ -n "$host_ip" ]; then
      printf "\n--- host-ip /healthz (%s) ---\n" "$host_ip"
      curl -sS -m 8 -o /tmp/mscqr-hostip-healthz.body -w "http_status=%{http_code} total_time=%{time_total}\n" "http://$host_ip/healthz" 2>&1 || true
      head -n 8 /tmp/mscqr-hostip-healthz.body 2>/dev/null || true
    fi
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

asg_json="$out_dir/asg-$timestamp.json"
target_health_json="$out_dir/target-health-$timestamp.json"
target_summary_json="$out_dir/asg-target-health-summary-$timestamp.json"
target_summary_env="$out_dir/asg-target-health-summary-$timestamp.env"

aws autoscaling describe-auto-scaling-groups \
  --region "$AWS_REGION" \
  --auto-scaling-group-names "$ASG_NAME" \
  --output json > "$asg_json"

aws elbv2 describe-target-health \
  --region "$AWS_REGION" \
  --target-group-arn "$TARGET_GROUP_ARN" \
  --output json > "$target_health_json"

DESIRED_CAPACITY="$(node -e 'const fs=require("fs"); const asg=JSON.parse(fs.readFileSync(process.argv[1],"utf8")).AutoScalingGroups?.[0]; console.log(asg?.DesiredCapacity ?? 0);' "$asg_json")"

node scripts/dr/check-asg-target-health-accounting.mjs \
  --asg-json "$asg_json" \
  --target-health-json "$target_health_json" \
  --desired "$DESIRED_CAPACITY" \
  --out-json "$target_summary_json" \
  --no-fail > "$target_summary_env"

run_section "ASG-only target health summary" print_asg_target_health_summary

ASG_INSTANCE_IDS="$(node -e 'const fs=require("fs"); const asg=JSON.parse(fs.readFileSync(process.argv[1],"utf8")).AutoScalingGroups?.[0]; for (const instance of asg?.Instances || []) console.log(instance.InstanceId);' "$asg_json")"

{
  printf '\n=== Current ASG instance IDs ===\n'
  printf '%s\n' "$ASG_INSTANCE_IDS"
} >> "$log_file"

set -- $ASG_INSTANCE_IDS
run_section "All current ASG instance IPs" collect_all_instance_ips "$@"

for instance_id do
  [ -n "$instance_id" ] || continue
  run_section "Instance $instance_id IPs" collect_instance_ips "$instance_id"
  run_section "Instance $instance_id ASG target health" collect_instance_target_health "$instance_id"
  run_section "Instance $instance_id filtered console output" safe_console_output "$instance_id"
  public_ip="$(get_instance_public_ip "$instance_id")"
  run_section "Instance $instance_id public /healthz curl" curl_public_health "$instance_id" "$public_ip"
  run_section "Instance $instance_id optional SSH deep inspection" ssh_deep_inspection "$instance_id" "$public_ip"
done

gzip -kf "$log_file"

printf 'Evidence log: %s\n' "$log_file"
printf 'Gzipped evidence log: %s.gz\n' "$log_file"
