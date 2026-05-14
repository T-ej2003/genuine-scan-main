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
  selected_json="$2"
  selected_tsv="$3"
  node --input-type=module - "$subnets_json" "$selected_json" "$selected_tsv" <<'NODE'
import fs from "node:fs";

const [inputPath, selectedJsonPath, selectedTsvPath] = process.argv.slice(2);
const payload = JSON.parse(fs.readFileSync(inputPath, "utf8"));
const subnets = Array.isArray(payload.Subnets) ? payload.Subnets : [];
const candidates = subnets
  .filter((subnet) => subnet.SubnetId && subnet.AvailabilityZone)
  .map((subnet) => ({
    SubnetId: subnet.SubnetId,
    AvailabilityZone: subnet.AvailabilityZone,
    AvailabilityZoneId: subnet.AvailabilityZoneId || "",
    VpcId: subnet.VpcId || "",
    CidrBlock: subnet.CidrBlock || "",
    MapPublicIpOnLaunch: Boolean(subnet.MapPublicIpOnLaunch),
    AvailableIpAddressCount: subnet.AvailableIpAddressCount ?? null,
    State: subnet.State || "",
  }))
  .sort((left, right) => {
    if (left.AvailabilityZone !== right.AvailabilityZone) {
      return left.AvailabilityZone.localeCompare(right.AvailabilityZone);
    }
    if (left.MapPublicIpOnLaunch !== right.MapPublicIpOnLaunch) {
      return left.MapPublicIpOnLaunch ? -1 : 1;
    }
    return left.SubnetId.localeCompare(right.SubnetId);
  });

const selectedByAz = new Map();
for (const subnet of candidates) {
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
    .map((subnet) => `${subnet.SubnetId}\t${subnet.AvailabilityZone}\t${subnet.MapPublicIpOnLaunch}`)
    .join("\n") + (selected.length > 0 ? "\n" : ""),
);

if (selected.length < 2) {
  console.error(
    `ALB requires at least two distinct Availability Zones; found ${selected.length}. Review ${selectedJsonPath}.`,
  );
  process.exit(2);
}

console.log(selected.map((subnet) => subnet.SubnetId).join(" "));
NODE
}
