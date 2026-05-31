#!/bin/sh

repo_root() {
  git rev-parse --show-toplevel 2>/dev/null
}

require_repo_root() {
  root="$(repo_root || true)"
  if [ -z "$root" ] || [ ! -f "$root/package.json" ] || [ ! -d "$root/.git" ]; then
    echo "Run this command from inside the MSCQR repository." >&2
    exit 1
  fi
  cd "$root"
}

utc_timestamp() {
  /bin/date -u '+%Y%m%dT%H%M%SZ'
}

ensure_artifact_root() {
  /bin/mkdir -p artifacts/dr
  {
    printf '%s\n' '*'
    printf '%s\n' '!.gitignore'
  } > artifacts/dr/.gitignore
}

create_artifact_dir() {
  ensure_artifact_root
  DR_TIMESTAMP="$(utc_timestamp)"
  DR_ARTIFACT_DIR="artifacts/dr/$DR_TIMESTAMP"
  /bin/mkdir -p "$DR_ARTIFACT_DIR"
}

validate_target() {
  case "$1" in
    mumbai|capetown|standby|standby_regions) ;;
    *)
      echo "Unsupported target: $1" >&2
      echo "Allowed targets: mumbai, capetown, standby, standby_regions" >&2
      exit 2
      ;;
  esac
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 127
  fi
}

run_logged() {
  log_file="$1"
  shift
  set +e
  "$@" > "$log_file" 2>&1
  status="$?"
  set -e
  /bin/cat "$log_file"
  return "$status"
}

json_escape() {
  node --input-type=module -e 'process.stdout.write(JSON.stringify(process.argv[1] || "").slice(1, -1));' "$1"
}

print_missing() {
  name="$1"
  echo "Missing required value: $name" >&2
}

select_unique_az_alb_subnets() {
  subnets_json="$1"
  route_tables_json="$2"
  selected_json="$3"
  selected_tsv="$4"
  node --input-type=module - "$subnets_json" "$route_tables_json" "$selected_json" "$selected_tsv" <<'NODE'
import fs from "node:fs";

const [subnetsPath, routeTablesPath, selectedJsonPath, selectedTsvPath] = process.argv.slice(2);
const subnetPayload = JSON.parse(fs.readFileSync(subnetsPath, "utf8"));
const routeTablePayload = JSON.parse(fs.readFileSync(routeTablesPath, "utf8"));
const subnets = Array.isArray(subnetPayload.Subnets) ? subnetPayload.Subnets : [];
const routeTables = Array.isArray(routeTablePayload.RouteTables) ? routeTablePayload.RouteTables : [];
const routeTableById = new Map(routeTables.map((routeTable) => [routeTable.RouteTableId, routeTable]));
const subnetRouteTableBySubnetId = new Map();
let mainRouteTable = null;

for (const routeTable of routeTables) {
  for (const association of routeTable.Associations || []) {
    if (association.SubnetId) {
      subnetRouteTableBySubnetId.set(association.SubnetId, routeTable);
    }
    if (association.Main) {
      mainRouteTable = routeTable;
    }
  }
}

function effectiveRouteTable(subnetId) {
  return subnetRouteTableBySubnetId.get(subnetId) || mainRouteTable || null;
}

function publicIgwRoute(routeTable) {
  for (const route of routeTable?.Routes || []) {
    if (
      route.DestinationCidrBlock === "0.0.0.0/0" &&
      typeof route.GatewayId === "string" &&
      route.GatewayId.startsWith("igw-") &&
      route.State !== "blackhole"
    ) {
      return route;
    }
  }
  return null;
}

const candidates = subnets
  .filter((subnet) => subnet.SubnetId && subnet.AvailabilityZone)
  .map((subnet) => {
    const routeTable = effectiveRouteTable(subnet.SubnetId);
    const route = publicIgwRoute(routeTable);
    return {
      SubnetId: subnet.SubnetId,
      AvailabilityZone: subnet.AvailabilityZone,
      AvailabilityZoneId: subnet.AvailabilityZoneId || "",
      VpcId: subnet.VpcId || "",
      CidrBlock: subnet.CidrBlock || "",
      MapPublicIpOnLaunch: Boolean(subnet.MapPublicIpOnLaunch),
      AvailableIpAddressCount: subnet.AvailableIpAddressCount ?? null,
      State: subnet.State || "",
      EffectiveRouteTableId: routeTable?.RouteTableId || "",
      HasPublicIgwRoute: Boolean(route),
      PublicIgwRouteGatewayId: route?.GatewayId || "",
    };
  })
  .sort((left, right) => {
    if (left.AvailabilityZone !== right.AvailabilityZone) {
      return left.AvailabilityZone.localeCompare(right.AvailabilityZone);
    }
    if (left.HasPublicIgwRoute !== right.HasPublicIgwRoute) {
      return left.HasPublicIgwRoute ? -1 : 1;
    }
    if (left.MapPublicIpOnLaunch !== right.MapPublicIpOnLaunch) {
      return left.MapPublicIpOnLaunch ? -1 : 1;
    }
    return left.SubnetId.localeCompare(right.SubnetId);
  });

const selectedByAz = new Map();
for (const subnet of candidates) {
  if (!subnet.HasPublicIgwRoute) continue;
  if (!selectedByAz.has(subnet.AvailabilityZone)) {
    selectedByAz.set(subnet.AvailabilityZone, subnet);
  }
}

const selected = [...selectedByAz.values()];
fs.writeFileSync(
  selectedJsonPath,
  JSON.stringify({ Candidates: candidates, SelectedSubnets: selected }, null, 2),
);
fs.writeFileSync(
  selectedTsvPath,
  selected
    .map((subnet) => `${subnet.SubnetId}\t${subnet.AvailabilityZone}\t${subnet.MapPublicIpOnLaunch}\t${subnet.EffectiveRouteTableId}\t${subnet.HasPublicIgwRoute}`)
    .join("\n") + (selected.length > 0 ? "\n" : ""),
);

if (selected.length < 2) {
  console.error(
    `Internet-facing ALB requires at least two distinct Availability Zones with 0.0.0.0/0 routes to igw-*; found ${selected.length}. Review ${selectedJsonPath}.`,
  );
  process.exit(2);
}

console.log(selected.map((subnet) => subnet.SubnetId).join(" "));
NODE
}

render_asg_rolling_policy_env() {
  policy_path="$1"
  target_region_group="$2"
  output_path="$3"

  if [ ! -f "$policy_path" ]; then
    echo "ASG rolling policy checklist not found: $policy_path" >&2
    exit 2
  fi

  node --input-type=module - "$policy_path" "$target_region_group" "$output_path" <<'NODE'
import fs from "node:fs";

const [policyPath, regionGroup, outputPath] = process.argv.slice(2);
const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));

const fail = (message) => {
  console.error(message);
  process.exit(2);
};

const asInt = (value, field) => {
  if (!Number.isInteger(value)) fail(`ASG rolling policy field ${field} must be an integer.`);
  return value;
};

if (!["mumbai", "capetown"].includes(regionGroup)) {
  fail(`Unsupported ASG rolling policy region group: ${regionGroup}`);
}

if (!["CONDITIONALLY_READY", "READY"].includes(String(policy.asgStatus || ""))) {
  fail(`ASG rolling policy checklist must be CONDITIONALLY_READY or READY; found ${policy.asgStatus || "unset"}.`);
}

const healthCheckType = String(policy.health_check_type || "");
if (healthCheckType !== "ELB") fail("ASG rolling policy must use ELB health checks.");

const deregistrationDelaySeconds = asInt(policy.deregistration_delay_seconds, "deregistration_delay_seconds");
if (deregistrationDelaySeconds < 60) fail("ASG rolling policy must keep deregistration_delay_seconds >= 60.");

const healthCheckGracePeriodSeconds = asInt(policy.health_check_grace_period_seconds, "health_check_grace_period_seconds");
if (healthCheckGracePeriodSeconds < 900) fail("ASG rolling policy must keep health_check_grace_period_seconds >= 900 for cold Ubuntu bootstrap.");

const defaultInstanceWarmupSeconds = asInt(policy.default_instance_warmup_seconds, "default_instance_warmup_seconds");
if (defaultInstanceWarmupSeconds < 900) fail("ASG rolling policy must keep default_instance_warmup_seconds >= 900 for cold Ubuntu bootstrap.");

const minHealthyPercentage = asInt(policy.instance_refresh_min_healthy_percentage, "instance_refresh_min_healthy_percentage");
if (minHealthyPercentage < 100) fail("ASG rolling policy must keep instance_refresh_min_healthy_percentage >= 100 for the first rollout.");

const maxHealthyPercentage = asInt(policy.instance_refresh_max_healthy_percentage, "instance_refresh_max_healthy_percentage");
if (maxHealthyPercentage < minHealthyPercentage) fail("ASG rolling policy max healthy percentage must be >= min healthy percentage.");

const checkpointDelaySeconds = asInt(policy.instance_refresh_checkpoint_delay_seconds, "instance_refresh_checkpoint_delay_seconds");
const desiredCapacityInitial = asInt(policy.desired_capacity_initial, "desired_capacity_initial");
const minSizeInitial = asInt(policy.min_size_initial, "min_size_initial");
const maxSizeInitial = asInt(policy.max_size_initial, "max_size_initial");
const targetGroupHealthRequired = asInt(policy.target_group_health_required, "target_group_health_required");

if (minSizeInitial < 2 || desiredCapacityInitial < 2) {
  fail("ASG rolling policy must keep min_size_initial and desired_capacity_initial >= 2.");
}
if (maxSizeInitial < desiredCapacityInitial) {
  fail("ASG rolling policy max_size_initial must be >= desired_capacity_initial.");
}
if (targetGroupHealthRequired < 2) {
  fail("ASG rolling policy target_group_health_required must be >= 2.");
}
if (policy.no_production_dns_cutover_during_validation !== true) {
  fail("ASG rolling policy must keep no_production_dns_cutover_during_validation=true.");
}
if (policy.replacement_instance_drill_required !== true) {
  fail("ASG rolling policy must keep replacement_instance_drill_required=true.");
}

const checkpointPercentages = Array.isArray(policy.instance_refresh_checkpoint_percentages)
  ? policy.instance_refresh_checkpoint_percentages.map((value) => asInt(value, "instance_refresh_checkpoint_percentages"))
  : [];
if (checkpointPercentages.length === 0) {
  fail("ASG rolling policy must define instance_refresh_checkpoint_percentages.");
}

const smokeTests = Array.isArray(policy.smoke_tests) ? policy.smoke_tests : [];
const smokeTestNames = new Set(smokeTests.map((item) => String(item)));
for (const required of [
  "/healthz",
  "/api/health/ready",
  "target_group_healthy_count",
  "alb_5xx",
  "target_5xx",
  "target_response_time",
]) {
  if (!smokeTestNames.has(required)) fail(`ASG rolling policy smoke_tests must include ${required}.`);
}

const rollbackAlarmNames = policy.rollback_alarm_names?.[regionGroup];
if (!Array.isArray(rollbackAlarmNames) || rollbackAlarmNames.length === 0) {
  fail(`ASG rolling policy must define rollback_alarm_names for ${regionGroup}.`);
}

const shellEscape = (value) => `'${String(value).replace(/'/g, `'\"'\"'`)}'`;

const lines = [
  `ASG_POLICY_STATUS=${shellEscape(String(policy.asgStatus))}`,
  `ASG_POLICY_HEALTH_CHECK_TYPE=${shellEscape(healthCheckType)}`,
  `ASG_POLICY_DEREGISTRATION_DELAY_SECONDS=${shellEscape(String(deregistrationDelaySeconds))}`,
  `ASG_POLICY_HEALTH_CHECK_GRACE_PERIOD_SECONDS=${shellEscape(String(healthCheckGracePeriodSeconds))}`,
  `ASG_POLICY_DEFAULT_INSTANCE_WARMUP_SECONDS=${shellEscape(String(defaultInstanceWarmupSeconds))}`,
  `ASG_POLICY_INSTANCE_REFRESH_MIN_HEALTHY_PERCENTAGE=${shellEscape(String(minHealthyPercentage))}`,
  `ASG_POLICY_INSTANCE_REFRESH_MAX_HEALTHY_PERCENTAGE=${shellEscape(String(maxHealthyPercentage))}`,
  `ASG_POLICY_INSTANCE_REFRESH_CHECKPOINT_DELAY_SECONDS=${shellEscape(String(checkpointDelaySeconds))}`,
  `ASG_POLICY_INSTANCE_REFRESH_CHECKPOINT_PERCENTAGES_CSV=${shellEscape(checkpointPercentages.join(","))}`,
  `ASG_POLICY_DESIRED_CAPACITY_INITIAL=${shellEscape(String(desiredCapacityInitial))}`,
  `ASG_POLICY_MIN_SIZE_INITIAL=${shellEscape(String(minSizeInitial))}`,
  `ASG_POLICY_MAX_SIZE_INITIAL=${shellEscape(String(maxSizeInitial))}`,
  `ASG_POLICY_TARGET_GROUP_HEALTH_REQUIRED=${shellEscape(String(targetGroupHealthRequired))}`,
  `ASG_POLICY_NO_PRODUCTION_DNS_CUTOVER_DURING_VALIDATION=${shellEscape("true")}`,
  `ASG_POLICY_REPLACEMENT_INSTANCE_DRILL_REQUIRED=${shellEscape("true")}`,
  `ASG_POLICY_ROLLBACK_ALARM_NAMES_CSV=${shellEscape(rollbackAlarmNames.join(","))}`,
  `ASG_POLICY_ROLLBACK_ALARM_PLACEHOLDERS_PRESENT=${shellEscape(rollbackAlarmNames.some((name) => /<[^>]+>/.test(String(name))) ? "true" : "false")}`,
  `ASG_POLICY_PATH=${shellEscape(policyPath)}`,
];

  fs.writeFileSync(outputPath, `${lines.join("\n")}\n`);
NODE
}

write_asg_web_launch_template_json() {
  output_path="$1"
  launch_template_name="$2"
  source_ami="$3"
  source_instance_type="$4"
  source_security_group="$5"
  target_region_group="$6"
  aws_region="$7"
  asg_web_instance_profile_arn="$8"
  asg_web_instance_profile_name="$9"
  asg_associate_public_ip="${10:-false}"
  asg_key_name="${11:-}"
  asg_repo_url="${12:-}"
  asg_repo_branch="${13:-main}"
  asg_repo_dir="${14:-/home/ubuntu/genuine-scan-main}"
  wrapper_mode="${15:-data}"

  if [ -z "$asg_web_instance_profile_arn" ] && [ -z "$asg_web_instance_profile_name" ]; then
    echo "ASG_WEB_INSTANCE_PROFILE_ARN or ASG_WEB_INSTANCE_PROFILE_NAME is required. Do not reuse the source instance profile implicitly." >&2
    exit 2
  fi

  case "$asg_associate_public_ip" in
    true|false) ;;
    *) echo "ASG_ASSOCIATE_PUBLIC_IP must be true or false." >&2; exit 2 ;;
  esac

  case "$asg_key_name" in
    *[[:space:]]*) echo "ASG_KEY_NAME must not contain whitespace." >&2; exit 2 ;;
  esac

  if [ -z "$asg_repo_url" ]; then
    echo "ASG_REPO_URL is required for self-sufficient ASG web-node bootstrap." >&2
    exit 2
  fi

  case "$asg_repo_url" in
    *[[:space:]]*|*@*) echo "ASG_REPO_URL must be a non-secret URL without whitespace or embedded credentials." >&2; exit 2 ;;
  esac
  case "$asg_repo_branch" in
    ""|*[[:space:]]*) echo "ASG_REPO_BRANCH must be non-empty and must not contain whitespace." >&2; exit 2 ;;
  esac
  case "$asg_repo_dir" in
    ""|*[[:space:]]*) echo "ASG_REPO_DIR must be non-empty and must not contain whitespace." >&2; exit 2 ;;
  esac

  node --input-type=module - "$output_path" "$launch_template_name" "$source_ami" "$source_instance_type" "$source_security_group" "$target_region_group" "$aws_region" "$asg_web_instance_profile_arn" "$asg_web_instance_profile_name" "$asg_associate_public_ip" "$asg_key_name" "$asg_repo_url" "$asg_repo_branch" "$asg_repo_dir" "$wrapper_mode" <<'NODE'
import fs from "node:fs";

const [
  outputPath,
  launchTemplateName,
  imageId,
  instanceType,
  securityGroup,
  regionGroup,
  awsRegion,
  profileArn,
  profileName,
  associatePublicIp,
  keyName,
  repoUrl,
  repoBranch,
  repoDir,
  wrapperMode,
] = process.argv.slice(2);

const fail = (message) => {
  console.error(message);
  process.exit(2);
};

for (const [name, value] of Object.entries({
  outputPath,
  imageId,
  instanceType,
  securityGroup,
  regionGroup,
  awsRegion,
  repoUrl,
  repoBranch,
  repoDir,
})) {
  if (!value) fail(`Missing required launch template value: ${name}`);
}

if (/\s/.test(repoUrl) || repoUrl.includes("@")) {
  fail("ASG_REPO_URL must be a non-secret URL without whitespace or embedded credentials.");
}
if (/\s/.test(repoBranch)) fail("ASG_REPO_BRANCH must not contain whitespace.");
if (/\s/.test(repoDir)) fail("ASG_REPO_DIR must not contain whitespace.");

const userData = `#!/bin/sh
set -eu

log_file="/var/log/mscqr-asg-bootstrap.log"
current_step="initializing"
TARGET_REGION_GROUP="${regionGroup}"
AWS_REGION="${awsRegion}"
ASG_REPO_URL="${repoUrl}"
ASG_REPO_BRANCH="${repoBranch}"
ASG_REPO_DIR="${repoDir}"
DOCKER_COMPOSE_VERSION="v2.29.7"
NODE_MAJOR="24"
NODE_MAX_MAJOR="27"
NPM_MIN_MAJOR="11"
NPM_VERSION="11.16.0"
export TARGET_REGION_GROUP AWS_REGION ASG_REPO_URL ASG_REPO_BRANCH ASG_REPO_DIR DOCKER_COMPOSE_VERSION NODE_MAJOR NODE_MAX_MAJOR NPM_MIN_MAJOR NPM_VERSION

log() {
  /usr/bin/printf "%s %s\\n" "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | /usr/bin/tee -a "$log_file"
}

safe_diag_cmd() {
  label="$1"
  shift
  log "diagnostic: $label"
  "$@" 2>&1 | /usr/bin/sed 's/^/  /' | /usr/bin/tee -a "$log_file" || true
}

safe_diagnostics() {
  log "running non-secret diagnostics"
  safe_diag_cmd "pwd" /bin/pwd
  if [ -e /home/ubuntu ]; then
    safe_diag_cmd "home directory listing" /bin/ls -ld /home/ubuntu
  fi
  if [ -n "$ASG_REPO_DIR" ] && [ -e "$ASG_REPO_DIR" ]; then
    log "diagnostic: repo dir exists: yes"
    safe_diag_cmd "repo directory listing" /bin/ls -ld "$ASG_REPO_DIR"
  else
    log "diagnostic: repo dir exists: no"
  fi
  if command -v git >/dev/null 2>&1; then
    safe_diag_cmd "git version" git --version
  fi
  if [ -d "$ASG_REPO_DIR/.git" ]; then
    (cd "$ASG_REPO_DIR" && safe_diag_cmd "git short HEAD" git rev-parse --short HEAD)
  fi
  if command -v docker >/dev/null 2>&1; then
    safe_diag_cmd "docker version" docker --version
    safe_diag_cmd "docker compose version" docker compose version
  fi
  if command -v aws >/dev/null 2>&1; then
    safe_diag_cmd "aws cli version" aws --version
  fi
  if command -v node >/dev/null 2>&1; then
    safe_diag_cmd "node version" node --version
  fi
  if command -v npm >/dev/null 2>&1; then
    safe_diag_cmd "npm version" npm --version
  fi
  if command -v systemctl >/dev/null 2>&1; then
    safe_diag_cmd "docker service state" systemctl is-active docker
  fi
}

on_exit() {
  status="$?"
  if [ "$status" -ne 0 ]; then
    log "MSCQR ASG bootstrap failed during step: $current_step"
    log "MSCQR ASG bootstrap failed; inspect /var/log/mscqr-asg-bootstrap.log and cloud-init-output.log"
    safe_diagnostics
  fi
  exit "$status"
}
trap on_exit EXIT

log "MSCQR ASG bootstrap starting"
log "writing log path: $log_file"

current_step="checking packages"
log "checking packages"
export DEBIAN_FRONTEND=noninteractive
if ! command -v git >/dev/null 2>&1; then
  current_step="installing git"
  log "installing git"
  apt-get update >> "$log_file" 2>&1
  apt-get install -y git ca-certificates curl >> "$log_file" 2>&1
else
  log "git already installed"
fi

if ! command -v docker >/dev/null 2>&1; then
  current_step="installing docker"
  log "installing docker"
  apt-get update >> "$log_file" 2>&1
  apt-get install -y docker.io >> "$log_file" 2>&1
else
  log "docker already installed"
fi

current_step="starting docker"
log "starting docker"
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now docker >> "$log_file" 2>&1
else
  service docker start >> "$log_file" 2>&1 || true
fi
if id ubuntu >/dev/null 2>&1 && getent group docker >/dev/null 2>&1; then
  usermod -aG docker ubuntu >> "$log_file" 2>&1 || true
fi

ensure_compose_download_prereqs() {
  if ! command -v curl >/dev/null 2>&1 || ! dpkg -s ca-certificates >/dev/null 2>&1; then
    current_step="installing docker compose download prerequisites"
    log "installing docker compose download prerequisites"
    apt-get update >> "$log_file" 2>&1
    apt-get install -y curl ca-certificates >> "$log_file" 2>&1
  fi
}

install_compose_plugin_from_pinned_release() {
  current_step="installing docker compose plugin from pinned release"
  log "installing docker compose plugin from pinned release $DOCKER_COMPOSE_VERSION"
  ensure_compose_download_prereqs

  arch_raw="$(uname -m)"
  case "$arch_raw" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)
      log "unsupported architecture for docker compose plugin: $arch_raw"
      return 1
      ;;
  esac

  plugin_dir="/usr/local/lib/docker/cli-plugins"
  plugin_path="/usr/local/lib/docker/cli-plugins/docker-compose"
  tmp_path="$(mktemp)"
  /bin/mkdir -p "$plugin_dir"

  if ! curl -fsSL "https://github.com/docker/compose/releases/download/\${DOCKER_COMPOSE_VERSION}/docker-compose-linux-\${ARCH}" -o "$tmp_path" >> "$log_file" 2>&1; then
    log "failed to install docker compose plugin from pinned release"
    /bin/rm -f "$tmp_path"
    return 1
  fi

  /bin/cp "$tmp_path" "$plugin_path"
  /bin/chmod +x "$plugin_path"
  /bin/rm -f "$tmp_path"

  if ! docker compose version >> "$log_file" 2>&1; then
    log "failed to install docker compose plugin from pinned release"
    return 1
  fi
}

current_step="checking docker compose"
log "checking docker compose"
docker --version >> "$log_file" 2>&1
if docker compose version >> "$log_file" 2>&1; then
  log "docker compose already available"
else
  current_step="installing docker compose plugin with apt"
  log "docker compose not available; trying apt docker-compose-plugin"
  apt-get update >> "$log_file" 2>&1
  if apt-get install -y docker-compose-plugin >> "$log_file" 2>&1; then
    log "docker-compose-plugin installed from apt"
  else
    log "docker-compose-plugin was not available from apt"
  fi

  current_step="checking docker compose after apt"
  if docker compose version >> "$log_file" 2>&1; then
    log "docker compose available after apt plugin install"
  else
    if ! install_compose_plugin_from_pinned_release; then
      log "failed to install docker compose plugin from pinned release"
      exit 2
    fi
  fi
fi

current_step="verifying docker compose"
log "verifying docker compose"
docker compose version >> "$log_file" 2>&1

ensure_aws_cli_download_prereqs() {
  if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1 || ! dpkg -s ca-certificates >/dev/null 2>&1; then
    current_step="installing aws cli download prerequisites"
    log "installing aws cli download prerequisites"
    apt-get update >> "$log_file" 2>&1
    apt-get install -y curl unzip ca-certificates >> "$log_file" 2>&1
  fi
}

install_aws_cli_v2_from_official_installer() {
  current_step="installing aws cli v2 from pinned official installer"
  log "installing aws cli v2 from pinned official installer"
  ensure_aws_cli_download_prereqs

  arch_raw="$(uname -m)"
  case "$arch_raw" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)
      log "unsupported architecture for aws cli v2 installer: $arch_raw"
      return 1
      ;;
  esac

  aws_tmp_dir="$(mktemp -d)"
  aws_zip="$aws_tmp_dir/awscliv2.zip"
  if ! curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-\${ARCH}.zip" -o "$aws_zip" >> "$log_file" 2>&1; then
    log "failed to install aws cli v2 from official installer"
    /bin/rm -rf "$aws_tmp_dir"
    return 1
  fi
  if ! unzip -q "$aws_zip" -d "$aws_tmp_dir" >> "$log_file" 2>&1; then
    log "failed to install aws cli v2 from official installer"
    /bin/rm -rf "$aws_tmp_dir"
    return 1
  fi
  if ! "$aws_tmp_dir/aws/install" --update >> "$log_file" 2>&1; then
    log "failed to install aws cli v2 from official installer"
    /bin/rm -rf "$aws_tmp_dir"
    return 1
  fi
  /bin/rm -rf "$aws_tmp_dir"

  if ! aws --version >> "$log_file" 2>&1; then
    log "failed to verify aws cli after official installer"
    return 1
  fi
}

current_step="checking aws cli"
log "checking aws cli"
if aws --version >> "$log_file" 2>&1; then
  log "aws cli already available"
else
  current_step="installing aws cli from apt"
  log "installing aws cli from apt"
  apt-get update >> "$log_file" 2>&1
  if apt-get install -y awscli >> "$log_file" 2>&1; then
    log "awscli installed from apt"
  else
    log "awscli was not available from apt"
  fi

  current_step="verifying aws cli"
  log "verifying aws cli"
  if aws --version >> "$log_file" 2>&1; then
    log "aws cli available after apt install"
  else
    if ! install_aws_cli_v2_from_official_installer; then
      log "failed to install aws cli"
      exit 2
    fi
  fi
fi

current_step="verifying aws cli"
log "verifying aws cli"
aws --version >> "$log_file" 2>&1

verify_node_runtime() {
  if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    return 1
  fi

  node_version="$(node --version 2>/dev/null || true)"
  npm_version="$(npm --version 2>/dev/null || true)"
  node_major="$(/usr/bin/printf "%s" "$node_version" | /usr/bin/sed 's/^v//; s/[.].*$//')"
  npm_major="$(/usr/bin/printf "%s" "$npm_version" | /usr/bin/sed 's/[.].*$//')"

  case "$node_major" in
    ""|*[!0-9]*) return 1 ;;
  esac
  case "$npm_major" in
    ""|*[!0-9]*) return 1 ;;
  esac

  if [ "$node_major" -lt "$NODE_MAJOR" ] || [ "$node_major" -ge "$NODE_MAX_MAJOR" ]; then
    return 1
  fi
  if [ "$npm_major" -lt "$NPM_MIN_MAJOR" ]; then
    return 1
  fi
}

install_node_download_prereqs() {
  current_step="installing node download prerequisites"
  log "installing node download prerequisites"
  apt-get update >> "$log_file" 2>&1
  apt-get install -y curl ca-certificates gnupg >> "$log_file" 2>&1
}

install_node_from_pinned_nodesource_major() {
  current_step="installing node"
  log "installing node"
  install_node_download_prereqs

  /bin/mkdir -p /etc/apt/keyrings
  node_key_tmp="$(mktemp)"
  if ! curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key -o "$node_key_tmp" >> "$log_file" 2>&1; then
    log "failed to install node from pinned NodeSource major"
    /bin/rm -f "$node_key_tmp"
    return 1
  fi
  /bin/rm -f /etc/apt/keyrings/nodesource.gpg
  if ! gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg "$node_key_tmp" >> "$log_file" 2>&1; then
    log "failed to install node from pinned NodeSource major"
    /bin/rm -f "$node_key_tmp"
    return 1
  fi
  /bin/rm -f "$node_key_tmp"

  /usr/bin/printf "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_%s.x nodistro main\\n" "$NODE_MAJOR" > /etc/apt/sources.list.d/nodesource.list
  apt-get update >> "$log_file" 2>&1
  if ! apt-get install -y nodejs >> "$log_file" 2>&1; then
    log "failed to install node from pinned NodeSource major"
    return 1
  fi

  current_step="installing npm"
  log "installing npm"
  if ! command -v npm >/dev/null 2>&1; then
    log "failed to install node/npm"
    return 1
  fi
  if ! npm install -g "npm@$NPM_VERSION" >> "$log_file" 2>&1; then
    log "failed to install node/npm"
    return 1
  fi
}

current_step="checking node"
log "checking node"
if verify_node_runtime; then
  node --version >> "$log_file" 2>&1
  npm --version >> "$log_file" 2>&1
  log "node already available"
else
  if ! install_node_from_pinned_nodesource_major; then
    log "failed to install node/npm"
    exit 2
  fi
fi

current_step="verifying node"
log "verifying node"
if ! node --version >> "$log_file" 2>&1; then
  log "failed to install node/npm"
  exit 2
fi
if ! verify_node_runtime; then
  log "failed to install node/npm"
  exit 2
fi
log "node available"

current_step="verifying npm"
log "verifying npm"
if ! npm --version >> "$log_file" 2>&1; then
  log "failed to install node/npm"
  exit 2
fi
log "npm available"

current_step="checking repo directory"
log "checking repo directory: $ASG_REPO_DIR"
if [ -d "$ASG_REPO_DIR/.git" ]; then
  cd "$ASG_REPO_DIR"
  current_step="fetching origin branch"
  log "fetching origin $ASG_REPO_BRANCH from repo path $ASG_REPO_DIR"
  git fetch origin "$ASG_REPO_BRANCH" >> "$log_file" 2>&1

  current_step="resetting to origin branch"
  log "resetting to origin/$ASG_REPO_BRANCH"
  git reset --hard "origin/$ASG_REPO_BRANCH" >> "$log_file" 2>&1
elif [ -e "$ASG_REPO_DIR" ]; then
  log "repo directory exists but is not a git checkout: $ASG_REPO_DIR"
  exit 2
else
  current_step="cloning repo"
  log "cloning repo branch $ASG_REPO_BRANCH into $ASG_REPO_DIR"
  /bin/mkdir -p "$(/usr/bin/dirname "$ASG_REPO_DIR")"
  git clone --branch "$ASG_REPO_BRANCH" --depth 1 "$ASG_REPO_URL" "$ASG_REPO_DIR" >> "$log_file" 2>&1
  cd "$ASG_REPO_DIR"
fi

current_step="checking bootstrap script exists"
log "checking bootstrap script exists"
if [ ! -f scripts/dr/bootstrap-asg-web-node.sh ]; then
  log "missing scripts/dr/bootstrap-asg-web-node.sh after git refresh"
  exit 2
fi

current_step="making bootstrap script executable"
/bin/chmod +x scripts/dr/bootstrap-asg-web-node.sh

current_step="running bootstrap script"
log "running bootstrap script"
bootstrap_status_file="$(mktemp)"
(
  set +e
  scripts/dr/bootstrap-asg-web-node.sh "$TARGET_REGION_GROUP" "$AWS_REGION"
  /usr/bin/printf "%s\\n" "$?" > "$bootstrap_status_file"
) 2>&1 | /usr/bin/tee -a "$log_file"
bootstrap_status="1"
if [ -f "$bootstrap_status_file" ]; then
  bootstrap_status="$(/bin/cat "$bootstrap_status_file")"
fi
/bin/rm -f "$bootstrap_status_file"
case "$bootstrap_status" in
  0) ;;
  *)
    log "bootstrap script failed"
    exit "$bootstrap_status"
    ;;
esac

current_step="bootstrap complete"
log "bootstrap complete"
trap - EXIT
exit 0
`;

if (!["true", "false"].includes(associatePublicIp)) {
  fail("ASG_ASSOCIATE_PUBLIC_IP must be true or false.");
}
if (/\s/.test(keyName || "")) {
  fail("ASG_KEY_NAME must not contain whitespace.");
}

const data = {
  ImageId: imageId,
  InstanceType: instanceType,
  IamInstanceProfile: profileArn ? { Arn: profileArn } : { Name: profileName },
  UserData: Buffer.from(userData, "utf8").toString("base64"),
  MetadataOptions: {
    HttpTokens: "required",
    HttpEndpoint: "enabled",
    HttpPutResponseHopLimit: 2,
  },
  TagSpecifications: [
    {
      ResourceType: "instance",
      Tags: [
        { Key: "Project", Value: "MSCQR" },
        { Key: "Purpose", Value: "DR" },
        { Key: "RegionGroup", Value: regionGroup },
      ],
    },
  ],
};

if (keyName) {
  data.KeyName = keyName;
}

if (associatePublicIp === "true") {
  data.NetworkInterfaces = [
    {
      DeviceIndex: 0,
      AssociatePublicIpAddress: true,
      Groups: [securityGroup],
    },
  ];
} else {
  data.SecurityGroupIds = [securityGroup];
}

const payload = wrapperMode === "wrapper"
  ? { LaunchTemplateName: launchTemplateName, LaunchTemplateData: data }
  : data;

fs.writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`);
NODE
}

validate_asg_launch_template_json() {
  launch_template_path="$1"
  wrapper_mode="${2:-data}"
  expected_associate_public_ip="${3:-false}"
  expected_security_group="${4:-}"
  expected_key_name="${5:-}"
  expected_repo_url="${6:-}"
  expected_repo_branch="${7:-main}"
  expected_repo_dir="${8:-/home/ubuntu/genuine-scan-main}"

  case "$expected_associate_public_ip" in
    true|false) ;;
    *) echo "ASG_ASSOCIATE_PUBLIC_IP must be true or false." >&2; exit 2 ;;
  esac

  case "$expected_key_name" in
    *[[:space:]]*) echo "ASG_KEY_NAME must not contain whitespace." >&2; exit 2 ;;
  esac

  node --input-type=module - "$launch_template_path" "$wrapper_mode" "$expected_associate_public_ip" "$expected_security_group" "$expected_key_name" "$expected_repo_url" "$expected_repo_branch" "$expected_repo_dir" <<'NODE'
import fs from "node:fs";

const [launchTemplatePath, wrapperMode, expectedAssociatePublicIp, expectedSecurityGroup, expectedKeyName, expectedRepoUrl, expectedRepoBranch, expectedRepoDir] = process.argv.slice(2);
const payload = JSON.parse(fs.readFileSync(launchTemplatePath, "utf8"));
const data = wrapperMode === "wrapper" ? payload.LaunchTemplateData : payload;

const fail = (message) => {
  console.error(message);
  process.exit(2);
};

if (!data || typeof data !== "object") fail("Launch template data is missing.");
if (!data.ImageId) fail("Launch template data is missing ImageId.");
if (!data.InstanceType) fail("Launch template data is missing InstanceType.");
if (expectedAssociatePublicIp === "true") {
  if (Array.isArray(data.SecurityGroupIds)) {
    fail("Launch template data must not set top-level SecurityGroupIds when ASG_ASSOCIATE_PUBLIC_IP=true.");
  }
  const primaryInterface = Array.isArray(data.NetworkInterfaces) ? data.NetworkInterfaces[0] : null;
  if (!primaryInterface) fail("Launch template data is missing NetworkInterfaces[0].");
  if (primaryInterface.DeviceIndex !== 0) fail("NetworkInterfaces[0].DeviceIndex must be 0.");
  if (primaryInterface.AssociatePublicIpAddress !== true) {
    fail("NetworkInterfaces[0].AssociatePublicIpAddress must be true when ASG_ASSOCIATE_PUBLIC_IP=true.");
  }
  if (!Array.isArray(primaryInterface.Groups) || primaryInterface.Groups.length === 0) {
    fail("NetworkInterfaces[0].Groups must include the source security group.");
  }
  if (expectedSecurityGroup && !primaryInterface.Groups.includes(expectedSecurityGroup)) {
    fail("NetworkInterfaces[0].Groups must include SOURCE_SECURITY_GROUP.");
  }
} else {
  if (Array.isArray(data.NetworkInterfaces)) {
    fail("Launch template data must not set NetworkInterfaces when ASG_ASSOCIATE_PUBLIC_IP=false.");
  }
  if (!Array.isArray(data.SecurityGroupIds) || data.SecurityGroupIds.length === 0) {
    fail("Launch template data is missing SecurityGroupIds.");
  }
  if (expectedSecurityGroup && !data.SecurityGroupIds.includes(expectedSecurityGroup)) {
    fail("SecurityGroupIds must include SOURCE_SECURITY_GROUP.");
  }
}
if (!data.IamInstanceProfile || (!data.IamInstanceProfile.Arn && !data.IamInstanceProfile.Name)) {
  fail("Launch template data is missing explicit IamInstanceProfile.");
}
if (expectedKeyName) {
  if (data.KeyName !== expectedKeyName) fail("Launch template KeyName must equal ASG_KEY_NAME.");
} else if (Object.hasOwn(data, "KeyName")) {
  fail("Launch template data must omit KeyName when ASG_KEY_NAME is not set.");
}
if (!data.UserData) fail("Launch template data is missing UserData.");
if (data.MetadataOptions?.HttpTokens !== "required") {
  fail("Launch template data must set MetadataOptions.HttpTokens to required.");
}
if (data.MetadataOptions?.HttpEndpoint !== "enabled") {
  fail("Launch template data must set MetadataOptions.HttpEndpoint to enabled.");
}
if (!Object.hasOwn(data.MetadataOptions || {}, "HttpPutResponseHopLimit")) {
  fail("Launch template data must set MetadataOptions.HttpPutResponseHopLimit.");
}
if (!Number.isInteger(data.MetadataOptions.HttpPutResponseHopLimit) || data.MetadataOptions.HttpPutResponseHopLimit < 2) {
  fail("Launch template data must set MetadataOptions.HttpPutResponseHopLimit >= 2 for Docker ASG web nodes.");
}

let decoded = "";
try {
  decoded = Buffer.from(String(data.UserData), "base64").toString("utf8");
} catch {
  fail("Launch template UserData is not valid base64.");
}

if (!decoded.startsWith("#!/bin/sh\n")) fail("Launch template UserData must start with #!/bin/sh.");
for (const required of [
  "set -eu",
  "/var/log/mscqr-asg-bootstrap.log",
  "TARGET_REGION_GROUP=",
  "AWS_REGION=",
  "ASG_REPO_URL=",
  "ASG_REPO_BRANCH=",
  "ASG_REPO_DIR=",
  "export DEBIAN_FRONTEND=noninteractive",
  "checking packages",
  "installing git",
  "apt-get install -y git ca-certificates curl",
  "installing docker",
  "docker.io",
  "starting docker",
  "checking docker compose",
  "apt-get install -y docker-compose-plugin",
  "DOCKER_COMPOSE_VERSION=",
  "/usr/local/lib/docker/cli-plugins",
  "/usr/local/lib/docker/cli-plugins/docker-compose",
  "docker-compose-linux-${ARCH}",
  "x86_64|amd64",
  "aarch64|arm64",
  "failed to install docker compose plugin from pinned release",
  "docker compose version",
  "verifying docker compose",
  "checking aws cli",
  "apt-get install -y awscli",
  "installing aws cli v2 from pinned official installer",
  "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip",
  "apt-get install -y curl unzip ca-certificates",
  "aws --version",
  "verifying aws cli",
  "NODE_MAJOR=\"24\"",
  "NPM_MIN_MAJOR=\"11\"",
  "checking node",
  "https://deb.nodesource.com/node_%s.x",
  "apt-get install -y curl ca-certificates gnupg",
  "apt-get install -y nodejs",
  "npm install -g \"npm@$NPM_VERSION\"",
  "node --version",
  "npm --version",
  "verifying node",
  "node available",
  "verifying npm",
  "npm available",
  "failed to install node/npm",
  "git clone --branch \"$ASG_REPO_BRANCH\" --depth 1 \"$ASG_REPO_URL\" \"$ASG_REPO_DIR\"",
  "git fetch origin \"$ASG_REPO_BRANCH\"",
  "git reset --hard \"origin/$ASG_REPO_BRANCH\"",
  "repo directory exists but is not a git checkout",
  "cd \"$ASG_REPO_DIR\"",
  "bootstrap_status_file=\"$(mktemp)\"",
  "tee -a \"$log_file\"",
  "bootstrap script failed",
  "scripts/dr/bootstrap-asg-web-node.sh \"$TARGET_REGION_GROUP\" \"$AWS_REGION\"",
]) {
  if (!decoded.includes(required)) fail(`Launch template UserData is missing ${required}.`);
}
if (expectedRepoUrl && !decoded.includes(`ASG_REPO_URL="${expectedRepoUrl}"`)) {
  fail("Launch template UserData does not include the expected ASG_REPO_URL.");
}
if (expectedRepoBranch && !decoded.includes(`ASG_REPO_BRANCH="${expectedRepoBranch}"`)) {
  fail("Launch template UserData does not include the expected ASG_REPO_BRANCH.");
}
if (expectedRepoDir && !decoded.includes(`ASG_REPO_DIR="${expectedRepoDir}"`)) {
  fail("Launch template UserData does not include the expected ASG_REPO_DIR.");
}
if (/route53|change-resource-record-sets|DATABASE_URL|JWT_SECRET|OBJECT_STORAGE_SECRET_KEY/.test(decoded)) {
  fail("Launch template UserData contains forbidden DNS or secret-looking text.");
}
NODE
}
