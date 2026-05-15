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
if (healthCheckGracePeriodSeconds < 180) fail("ASG rolling policy must keep health_check_grace_period_seconds >= 180.");

const defaultInstanceWarmupSeconds = asInt(policy.default_instance_warmup_seconds, "default_instance_warmup_seconds");
if (defaultInstanceWarmupSeconds < 180) fail("ASG rolling policy must keep default_instance_warmup_seconds >= 180.");

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
  wrapper_mode="${10:-data}"

  if [ -z "$asg_web_instance_profile_arn" ] && [ -z "$asg_web_instance_profile_name" ]; then
    echo "ASG_WEB_INSTANCE_PROFILE_ARN or ASG_WEB_INSTANCE_PROFILE_NAME is required. Do not reuse the source instance profile implicitly." >&2
    exit 2
  fi

  node --input-type=module - "$output_path" "$launch_template_name" "$source_ami" "$source_instance_type" "$source_security_group" "$target_region_group" "$aws_region" "$asg_web_instance_profile_arn" "$asg_web_instance_profile_name" "$wrapper_mode" <<'NODE'
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
})) {
  if (!value) fail(`Missing required launch template value: ${name}`);
}

const userData = `#!/bin/sh
set -eu

log_file="/var/log/mscqr-asg-bootstrap.log"
exec >> "$log_file" 2>&1

echo "MSCQR ASG web-node bootstrap starting."
TARGET_REGION_GROUP="${regionGroup}"
AWS_REGION="${awsRegion}"
export TARGET_REGION_GROUP AWS_REGION

cd /home/ubuntu/genuine-scan-main

echo "Fetching approved main branch."
git fetch origin main
git reset --hard origin/main

if [ ! -f scripts/dr/bootstrap-asg-web-node.sh ]; then
  echo "Missing scripts/dr/bootstrap-asg-web-node.sh after git refresh."
  exit 2
fi

/bin/chmod +x scripts/dr/bootstrap-asg-web-node.sh

echo "Running MSCQR ASG web-node bootstrap."
scripts/dr/bootstrap-asg-web-node.sh "$TARGET_REGION_GROUP" "$AWS_REGION"

echo "MSCQR ASG web-node bootstrap completed."
`;

const data = {
  ImageId: imageId,
  InstanceType: instanceType,
  SecurityGroupIds: [securityGroup],
  IamInstanceProfile: profileArn ? { Arn: profileArn } : { Name: profileName },
  UserData: Buffer.from(userData, "utf8").toString("base64"),
  MetadataOptions: {
    HttpTokens: "required",
    HttpEndpoint: "enabled",
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

const payload = wrapperMode === "wrapper"
  ? { LaunchTemplateName: launchTemplateName, LaunchTemplateData: data }
  : data;

fs.writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`);
NODE
}

validate_asg_launch_template_json() {
  launch_template_path="$1"
  wrapper_mode="${2:-data}"

  node --input-type=module - "$launch_template_path" "$wrapper_mode" <<'NODE'
import fs from "node:fs";

const [launchTemplatePath, wrapperMode] = process.argv.slice(2);
const payload = JSON.parse(fs.readFileSync(launchTemplatePath, "utf8"));
const data = wrapperMode === "wrapper" ? payload.LaunchTemplateData : payload;

const fail = (message) => {
  console.error(message);
  process.exit(2);
};

if (!data || typeof data !== "object") fail("Launch template data is missing.");
if (!data.ImageId) fail("Launch template data is missing ImageId.");
if (!data.InstanceType) fail("Launch template data is missing InstanceType.");
if (!Array.isArray(data.SecurityGroupIds) || data.SecurityGroupIds.length === 0) {
  fail("Launch template data is missing SecurityGroupIds.");
}
if (!data.IamInstanceProfile || (!data.IamInstanceProfile.Arn && !data.IamInstanceProfile.Name)) {
  fail("Launch template data is missing explicit IamInstanceProfile.");
}
if (!data.UserData) fail("Launch template data is missing UserData.");
if (data.MetadataOptions?.HttpTokens !== "required") {
  fail("Launch template data must set MetadataOptions.HttpTokens to required.");
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
  "cd /home/ubuntu/genuine-scan-main",
  "git fetch origin main",
  "git reset --hard origin/main",
  "scripts/dr/bootstrap-asg-web-node.sh \"$TARGET_REGION_GROUP\" \"$AWS_REGION\"",
]) {
  if (!decoded.includes(required)) fail(`Launch template UserData is missing ${required}.`);
}
if (/route53|change-resource-record-sets|DATABASE_URL|JWT_SECRET|OBJECT_STORAGE_SECRET_KEY/.test(decoded)) {
  fail("Launch template UserData contains forbidden DNS or secret-looking text.");
}
NODE
}
