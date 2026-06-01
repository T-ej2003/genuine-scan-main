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
  READY_URL=https://www.mscqr.com/api/health/ready
  ALB_HTTP_HEALTHZ_URL=http://regional-alb.elb.amazonaws.com/healthz
  ALB_DNS_NAME=regional-alb.elb.amazonaws.com
  DR_HOSTNAME=dr-capetown.mscqr.com
  DR_HOST_SCHEME=https
  DR_HEALTH_PATH=/healthz

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
READY_URL="${READY_URL:-}"
ALB_DNS_NAME="${ALB_DNS_NAME:-}"
ALB_HTTP_HEALTHZ_URL="${ALB_HTTP_HEALTHZ_URL:-}"
DR_HOSTNAME="${DR_HOSTNAME:-}"
DR_HOST_SCHEME="${DR_HOST_SCHEME:-https}"
DR_HEALTH_PATH="${DR_HEALTH_PATH:-/healthz}"

[ -n "$TARGET_REGION_GROUP" ] || { echo "TARGET_REGION_GROUP is required." >&2; exit 1; }
[ -n "$AWS_REGION" ] || { echo "AWS_REGION is required." >&2; exit 1; }
[ -n "$ASG_NAME" ] || { echo "ASG_NAME is required." >&2; exit 1; }
[ -n "$TARGET_GROUP_ARN" ] || { echo "TARGET_GROUP_ARN is required." >&2; exit 1; }
command -v aws >/dev/null 2>&1 || { echo "aws CLI is required." >&2; exit 1; }

if [ -z "$ALB_DNS_NAME" ] && [ "$TARGET_REGION_GROUP" = "capetown" ]; then
  ALB_DNS_NAME="mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com"
fi

if [ -z "$ALB_HTTP_HEALTHZ_URL" ] && [ -n "$ALB_DNS_NAME" ]; then
  ALB_HTTP_HEALTHZ_URL="http://$ALB_DNS_NAME/healthz"
fi

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
    --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,LaunchTime:LaunchTime,PrivateIp:PrivateIpAddress,PublicIp:PublicIpAddress,Subnet:SubnetId,SecurityGroups:SecurityGroups[].GroupId,IamInstanceProfile:IamInstanceProfile.Arn,MetadataOptions:MetadataOptions}' \
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
    --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,LaunchTime:LaunchTime,PrivateIp:PrivateIpAddress,PublicIp:PublicIpAddress,SecurityGroups:SecurityGroups[].GroupId,IamInstanceProfile:IamInstanceProfile.Arn,MetadataOptions:MetadataOptions}' \
    --output table
}

collect_asg_final_state() {
  aws autoscaling describe-auto-scaling-groups \
    --region "$AWS_REGION" \
    --auto-scaling-group-names "$ASG_NAME" \
    --query 'AutoScalingGroups[0].{Name:AutoScalingGroupName,Min:MinSize,Desired:DesiredCapacity,Max:MaxSize,HealthCheckType:HealthCheckType,HealthCheckGracePeriod:HealthCheckGracePeriod,DefaultInstanceWarmup:DefaultInstanceWarmup,LaunchTemplate:LaunchTemplate,Instances:Instances[].{Id:InstanceId,Lifecycle:LifecycleState,Health:HealthStatus,AZ:AvailabilityZone}}' \
    --output json
}

get_instance_public_ip() {
  instance_id="$1"
  aws ec2 describe-instances \
    --region "$AWS_REGION" \
    --instance-ids "$instance_id" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text 2>/dev/null || true
}

collect_launch_template_metadata_options() {
  launch_template_id="$(node -e 'const fs=require("fs"); const asg=JSON.parse(fs.readFileSync(process.argv[1],"utf8")).AutoScalingGroups?.[0]; const lt=asg?.LaunchTemplate || asg?.MixedInstancesPolicy?.LaunchTemplate?.LaunchTemplateSpecification; console.log(lt?.LaunchTemplateId || "");' "$asg_json")"
  launch_template_version="$(node -e 'const fs=require("fs"); const asg=JSON.parse(fs.readFileSync(process.argv[1],"utf8")).AutoScalingGroups?.[0]; const lt=asg?.LaunchTemplate || asg?.MixedInstancesPolicy?.LaunchTemplate?.LaunchTemplateSpecification; console.log(lt?.Version || "$Default");' "$asg_json")"
  if [ -z "$launch_template_id" ]; then
    printf 'Launch template metadata: not available on ASG payload.\n'
    return 0
  fi
  printf 'LAUNCH_TEMPLATE_ID=%s\n' "$launch_template_id"
  printf 'LAUNCH_TEMPLATE_VERSION=%s\n' "$launch_template_version"
  aws ec2 describe-launch-template-versions \
    --region "$AWS_REGION" \
    --launch-template-id "$launch_template_id" \
    --versions "$launch_template_version" \
    --query 'LaunchTemplateVersions[].{Version:VersionNumber,Default:DefaultVersion,InstanceProfile:LaunchTemplateData.IamInstanceProfile,MetadataOptions:LaunchTemplateData.MetadataOptions}' \
    --output json
}

collect_instance_metadata_profile() {
  instance_id="$1"
  aws ec2 describe-instances \
    --region "$AWS_REGION" \
    --instance-ids "$instance_id" \
    --query 'Reservations[].Instances[].{Id:InstanceId,IamInstanceProfile:IamInstanceProfile,MetadataOptions:MetadataOptions}' \
    --output json
}

verify_instance_metadata_options() {
  instance_id="$1"
  metadata_json="$out_dir/metadata-options-$instance_id-$timestamp.json"
  aws ec2 describe-instances \
    --region "$AWS_REGION" \
    --instance-ids "$instance_id" \
    --query 'Reservations[0].Instances[0].MetadataOptions' \
    --output json > "$metadata_json"

  node -e '
const fs = require("fs");
const instanceId = process.argv[2];
const metadata = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const hopLimit = Number(metadata.HttpPutResponseHopLimit || 0);
const pass = metadata.HttpTokens === "required" && metadata.HttpEndpoint === "enabled" && hopLimit >= 2;
console.log(`INSTANCE_ID=${instanceId}`);
console.log(`HttpTokens=${metadata.HttpTokens || "unknown"}`);
console.log(`HttpEndpoint=${metadata.HttpEndpoint || "unknown"}`);
console.log(`HttpPutResponseHopLimit=${Number.isFinite(hopLimit) ? hopLimit : "unknown"}`);
console.log(`IMDS_METADATA_OPTIONS_CHECK=${pass ? "pass" : "fail"}`);
if (!pass) process.exit(1);
' "$metadata_json" "$instance_id"
}

curl_alb_http_healthz() {
  if [ -z "$ALB_HTTP_HEALTHZ_URL" ]; then
    printf 'ALB HTTP /healthz skipped: ALB_HTTP_HEALTHZ_URL not set.\n'
    return 0
  fi
  case "$ALB_HTTP_HEALTHZ_URL" in
    http://*) ;;
    https://*)
      printf 'ALB HTTP /healthz skipped: raw ALB HTTPS is intentionally not used because certificate hostname mismatch is expected. Use a real DR hostname for HTTPS validation.\n'
      return 0
      ;;
    *)
      printf 'ALB HTTP /healthz skipped: ALB_HTTP_HEALTHZ_URL must start with http:// for raw ALB evidence.\n'
      return 0
      ;;
  esac

  body_path="$out_dir/alb-http-healthz-$timestamp.body"
  meta_path="$out_dir/alb-http-healthz-$timestamp.meta"
  if curl -sS -m 10 -o "$body_path" -w 'http_status=%{http_code} total_time=%{time_total} remote_ip=%{remote_ip}\n' "$ALB_HTTP_HEALTHZ_URL" > "$meta_path" 2>&1; then
    printf 'ALB HTTP /healthz curl: ok '
  else
    printf 'ALB HTTP /healthz curl: failed '
  fi
  cat "$meta_path" 2>/dev/null || true
  printf 'ALB HTTP /healthz body snippet:\n'
  sed -n '1,8p' "$body_path" 2>/dev/null | tr -cd '\11\12\15\40-\176' || true
  printf '\n'
}

curl_dr_hostname_health() {
  if [ -z "$DR_HOSTNAME" ]; then
    printf 'DR hostname health skipped: DR_HOSTNAME not set.\n'
    return 0
  fi
  case "$DR_HEALTH_PATH" in
    /*) ;;
    *) printf 'DR hostname health skipped: DR_HEALTH_PATH must start with /.\n'; return 0 ;;
  esac
  case "$DR_HOST_SCHEME" in
    http|https) ;;
    *) printf 'DR hostname health skipped: DR_HOST_SCHEME must be http or https.\n'; return 0 ;;
  esac

  dr_url="$DR_HOST_SCHEME://$DR_HOSTNAME$DR_HEALTH_PATH"
  body_path="$out_dir/dr-hostname-health-$timestamp.body"
  meta_path="$out_dir/dr-hostname-health-$timestamp.meta"
  if curl -sS -m 12 -o "$body_path" -w 'http_status=%{http_code} total_time=%{time_total} remote_ip=%{remote_ip}\n' "$dr_url" > "$meta_path" 2>&1; then
    printf 'DR hostname health curl: ok '
  else
    printf 'DR hostname health curl: failed '
  fi
  cat "$meta_path" 2>/dev/null || true
  printf 'DR hostname health body snippet:\n'
  sed -n '1,8p' "$body_path" 2>/dev/null | tr -cd '\11\12\15\40-\176' || true
  printf '\n'
}

curl_object_storage_readiness() {
  ready_url="$READY_URL"
  if [ -z "$ready_url" ]; then
    case "$TARGET_REGION_GROUP" in
      mumbai) ready_url="https://www.mscqr.com/api/health/ready" ;;
      capetown)
        if [ -n "$ALB_DNS_NAME" ]; then
          ready_url="http://$ALB_DNS_NAME/api/health/ready"
        else
          ready_url="https://dr-capetown.mscqr.com/api/health/ready"
        fi
        ;;
      *) ready_url="" ;;
    esac
  fi
  if [ -z "$ready_url" ]; then
    printf 'Object storage readiness curl skipped: READY_URL not set.\n'
    return 0
  fi

  ready_body="$out_dir/object-storage-ready-$timestamp.body"
  ready_meta="$out_dir/object-storage-ready-$timestamp.meta"
  if curl -sS -m 12 -o "$ready_body" -w 'http_status=%{http_code} total_time=%{time_total} remote_ip=%{remote_ip}\n' "$ready_url" > "$ready_meta" 2>&1; then
    printf 'Readiness curl: ok '
  else
    printf 'Readiness curl: failed '
  fi
  cat "$ready_meta" 2>/dev/null || true
  node -e 'const fs=require("fs"); const file=process.argv[1]; if (!fs.existsSync(file)) process.exit(0); const sanitize=(value)=>typeof value==="string" ? value.replace(/([A-Za-z_]*(?:SECRET|PASSWORD|TOKEN|KEY)[A-Za-z_]*=)[^&\s]+/gi,"$1[redacted]").slice(0,240) : value; try { const payload=JSON.parse(fs.readFileSync(file,"utf8")); const objectStorage=payload.dependencies?.objectStorage || {}; console.log(JSON.stringify({success:payload.success===true,status:payload.status||"unknown",objectStorage:{configured:objectStorage.configured===true,ready:objectStorage.ready===true,bucket:objectStorage.bucket||null,region:objectStorage.region||null,endpointConfigured:Boolean(objectStorage.endpoint),mode:objectStorage.mode||null,reason:sanitize(objectStorage.reason||null)}})); } catch { console.log(sanitize(fs.readFileSync(file,"utf8")).slice(0,500)); }' "$ready_body" 2>/dev/null || true
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
  printf 'ALB_HTTP_HEALTHZ_URL=%s\n' "${ALB_HTTP_HEALTHZ_URL:-not-set}"
  printf 'DR_HOSTNAME=%s\n' "${DR_HOSTNAME:-not-set}"
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
run_section "Launch template metadata options and instance profile" collect_launch_template_metadata_options
run_section "Cape Town/raw ALB HTTP /healthz" curl_alb_http_healthz
run_section "Optional DR hostname health" curl_dr_hostname_health
run_section "Object storage readiness" curl_object_storage_readiness

asg_instance_ids_file="$out_dir/asg-instance-ids-$timestamp.txt"
node -e 'const fs=require("fs"); const asg=JSON.parse(fs.readFileSync(process.argv[1],"utf8")).AutoScalingGroups?.[0]; for (const instance of asg?.Instances || []) console.log(instance.InstanceId);' "$asg_json" > "$asg_instance_ids_file"
ASG_INSTANCE_IDS="$(/bin/cat "$asg_instance_ids_file")"

{
  printf '\n=== Current ASG instance IDs ===\n'
  printf 'Instance IDs are printed one per line and passed to AWS as separate arguments.\n'
  /bin/cat "$asg_instance_ids_file"
} >> "$log_file"

set -- $ASG_INSTANCE_IDS
run_section "All current ASG instance IPs" collect_all_instance_ips "$@"

for instance_id do
  [ -n "$instance_id" ] || continue
  run_section "Instance $instance_id IPs" collect_instance_ips "$instance_id"
  run_section "Instance $instance_id metadata options and profile" collect_instance_metadata_profile "$instance_id"
  run_section "Instance $instance_id IMDSv2 metadata options verification" verify_instance_metadata_options "$instance_id"
  run_section "Instance $instance_id ASG target health" collect_instance_target_health "$instance_id"
  run_section "Instance $instance_id filtered console output" safe_console_output "$instance_id"
  public_ip="$(get_instance_public_ip "$instance_id")"
  run_section "Instance $instance_id public /healthz curl" curl_public_health "$instance_id" "$public_ip"
  run_section "Instance $instance_id optional SSH deep inspection" ssh_deep_inspection "$instance_id" "$public_ip"
done

run_section "ASG final state" collect_asg_final_state

gzip -kf "$log_file"

printf 'Evidence log: %s\n' "$log_file"
printf 'Gzipped evidence log: %s.gz\n' "$log_file"
