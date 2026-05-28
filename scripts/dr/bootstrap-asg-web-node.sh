#!/bin/sh
set -eu

usage() {
  cat <<'USAGE'
Usage: scripts/dr/bootstrap-asg-web-node.sh <target_region_group> <aws_region>

Examples:
  scripts/dr/bootstrap-asg-web-node.sh mumbai ap-south-1
  scripts/dr/bootstrap-asg-web-node.sh capetown af-south-1

Environment overrides:
  TARGET_REGION_GROUP       mumbai or capetown
  AWS_REGION                AWS region for SSM and runtime
  SSM_PARAMETER_PREFIX      Override the default /mscqr/prod/<region>/asg-web/ path
  PROJECT_DIR               Repository checkout path
  ASG_BOOTSTRAP_SKIP_DOCKER Set true to render env files without starting containers
USAGE
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

is_true() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

target_region_group="${1:-${TARGET_REGION_GROUP:-}}"
aws_region="${2:-${AWS_REGION:-}}"

if [ "$target_region_group" = "-h" ] || [ "$target_region_group" = "--help" ]; then
  usage
  exit 0
fi

[ -n "$target_region_group" ] || die "target_region_group is required."

case "$target_region_group" in
  mumbai)
    aws_region="${aws_region:-ap-south-1}"
    default_prefix="/mscqr/prod/ap-south-1/asg-web/"
    ;;
  capetown)
    aws_region="${aws_region:-af-south-1}"
    default_prefix="/mscqr/prod/af-south-1/asg-web/"
    ;;
  *)
    die "target_region_group must be mumbai or capetown."
    ;;
esac

[ -n "$aws_region" ] || die "aws_region is required."

project_dir="${PROJECT_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}"
manifest_path="$project_dir/documents/ops/aws-asg-web-ssm-parameter-manifest.json"
root_env_path="$project_dir/.env"
backend_env_path="$project_dir/backend/.env"
ssm_prefix="${SSM_PARAMETER_PREFIX:-$default_prefix}"

case "$ssm_prefix" in
  */) ;;
  *) ssm_prefix="$ssm_prefix/" ;;
esac

[ -f "$manifest_path" ] || die "Missing manifest: $manifest_path"
command -v aws >/dev/null 2>&1 || die "aws CLI is required."
command -v node >/dev/null 2>&1 || die "node is required."

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/mscqr-asg-bootstrap.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
params_json="$tmp_dir/ssm-parameters.json"
compose_env_path="$tmp_dir/compose.env"

printf 'Fetching ASG web-node parameters from SSM path %s in %s...\n' "$ssm_prefix" "$aws_region"
aws ssm get-parameters-by-path \
  --path "$ssm_prefix" \
  --recursive \
  --with-decryption \
  --region "$aws_region" \
  --output json > "$params_json"

umask 077
node --input-type=module - "$manifest_path" "$params_json" "$ssm_prefix" "$root_env_path" "$backend_env_path" "$compose_env_path" "$aws_region" <<'NODE'
import fs from "node:fs";
import path from "node:path";

const [
  manifestPath,
  paramsPath,
  ssmPrefix,
  rootEnvPath,
  backendEnvPath,
  composeEnvPath,
  awsRegion,
] = process.argv.slice(2);

const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const paramsPayload = JSON.parse(fs.readFileSync(paramsPath, "utf8"));
const parameters = Array.isArray(paramsPayload.Parameters) ? paramsPayload.Parameters : [];
const values = new Map();

for (const parameter of parameters) {
  const name = String(parameter.Name || "");
  if (!name.startsWith(ssmPrefix)) continue;
  const key = name.slice(ssmPrefix.length).split("/").filter(Boolean).join("_");
  if (!key) continue;
  values.set(key, String(parameter.Value ?? ""));
}

const fail = (message) => {
  console.error(message);
  process.exit(1);
};

const formatMissingParameter = (key) => `${key} (${ssmPrefix}${key})`;

const assertPresent = (sectionName, keys) => {
  const missing = [];
  const empty = [];
  for (const key of keys || []) {
    if (!values.has(key)) {
      missing.push(key);
    } else if (values.get(key) === "") {
      empty.push(key);
    }
  }
  if (missing.length > 0) {
    fail(`${sectionName} missing required SSM parameter(s): ${missing.map(formatMissingParameter).join(", ")}`);
  }
  if (empty.length > 0) {
    fail(`${sectionName} required SSM parameter is empty: ${empty.map(formatMissingParameter).join(", ")}`);
  }
};

assertPresent("rootEnv", manifest.rootEnv?.requiredFromSsm || []);
assertPresent("backendEnv", manifest.backendEnv?.requiredFromSsm || []);

const parseBool = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());
const mergedKeys = new Set([
  ...(manifest.rootEnv?.requiredFromSsm || []),
  ...(manifest.rootEnv?.optionalFromSsm || []),
  ...(manifest.backendEnv?.requiredFromSsm || []),
  ...(manifest.backendEnv?.optionalFromSsm || []),
]);

for (const excluded of [...(manifest.rootEnv?.excluded || []), ...(manifest.backendEnv?.excluded || [])]) {
  if (values.has(excluded)) {
    fail(`Forbidden ASG web-node parameter is present in SSM: ${excluded}`);
  }
}

const buildSection = (section) => {
  const output = new Map();
  for (const key of section.requiredFromSsm || []) output.set(key, values.get(key) || "");
  for (const key of section.optionalFromSsm || []) {
    if (values.has(key)) output.set(key, values.get(key) || "");
  }
  for (const [key, value] of Object.entries(section.forced || {})) output.set(key, String(value));
  return output;
};

const rootEnv = buildSection(manifest.rootEnv || {});
const backendEnv = buildSection(manifest.backendEnv || {});
const composeEnv = new Map([...rootEnv.entries(), ...backendEnv.entries()]);

for (const key of ["AWS_REGION", "OBJECT_STORAGE_REGION"]) {
  if (rootEnv.get(key) !== awsRegion) {
    fail(`${key} must equal aws_region ${awsRegion}.`);
  }
}

if (!String(rootEnv.get("REDIS_URL") || "").startsWith("rediss://")) {
  fail("REDIS_URL must use rediss:// for ASG web nodes.");
}

const safetyExpectations = {
  RUN_BACKGROUND_WORKERS: "false",
  RUN_DB_MIGRATIONS_ON_START: "false",
  COMPLIANCE_PACK_SCHEDULER_ENABLED: "false",
  REDIS_TLS: "true",
  OBJECT_STORAGE_ENDPOINT: "",
  OBJECT_STORAGE_ACCESS_KEY: "",
  OBJECT_STORAGE_SECRET_KEY: "",
  OBJECT_STORAGE_FORCE_PATH_STYLE: "false",
};

for (const [key, expected] of Object.entries(safetyExpectations)) {
  const actual = backendEnv.has(key) ? backendEnv.get(key) : rootEnv.get(key);
  if (actual !== expected) fail(`${key} must be forced to ${JSON.stringify(expected)}.`);
}

if (!parseBool(backendEnv.get("COOKIE_SECURE"))) {
  fail("COOKIE_SECURE must be true for production ASG web nodes.");
}

const envEscape = (value) => {
  const raw = String(value ?? "");
  if (/^[A-Za-z0-9_./:@,+%=-]*$/.test(raw)) return raw;
  return JSON.stringify(raw);
};

const writeEnv = (filePath, sectionName, entries) => {
  const lines = [
    "# Generated by scripts/dr/bootstrap-asg-web-node.sh",
    "# Do not commit this file. Values are sourced from AWS SSM Parameter Store.",
    `# Section: ${sectionName}`,
    "",
  ];
  for (const [key, value] of [...entries.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    lines.push(`${key}=${envEscape(value)}`);
  }
  lines.push("");
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, lines.join("\n"), { mode: 0o600 });
  fs.renameSync(tmp, filePath);
  fs.chmodSync(filePath, 0o600);
};

writeEnv(backendEnvPath, "backendEnv", backendEnv);
writeEnv(rootEnvPath, "composeRootEnv", composeEnv);
writeEnv(composeEnvPath, "composeInterpolationEnv", composeEnv);

console.log(`Rendered ${composeEnv.size} project Compose env key(s) and ${backendEnv.size} backend env key(s).`);
console.log(`Rendered ${composeEnv.size} Compose interpolation env key(s) into a temporary env file.`);
console.log(`SSM parameter names consumed: ${parameters.length}. Values were not printed.`);
NODE

if is_true "${ASG_BOOTSTRAP_SKIP_DOCKER:-false}"; then
  printf 'ASG_BOOTSTRAP_SKIP_DOCKER=true; env files rendered and container startup skipped.\n'
  exit 0
fi

command -v docker >/dev/null 2>&1 || die "docker is required unless ASG_BOOTSTRAP_SKIP_DOCKER=true."
command -v curl >/dev/null 2>&1 || die "curl is required unless ASG_BOOTSTRAP_SKIP_DOCKER=true."

run_compose() {
  (
    cd "$project_dir"
    docker compose --env-file "$compose_env_path" -f docker-compose.asg-web.yml "$@"
  )
}

print_container_state() {
  container_name="$1"
  if ! docker inspect "$container_name" >/dev/null 2>&1; then
    printf '%s: container not found\n' "$container_name"
    return 0
  fi
  docker inspect --format='{{.Name}} state={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_name" 2>/dev/null || true
}

print_backend_health_summary() {
  if ! docker inspect genuine-scan-backend >/dev/null 2>&1; then
    printf 'backend health summary unavailable: backend container not found\n'
    return 0
  fi
  docker exec -i genuine-scan-backend node <<'NODE' 2>/dev/null || true
const http = require("node:http");

const summarize = (payload) => {
  const dependencies = payload.dependencies || {};
  const result = {
    success: payload.success === true,
    status: payload.status || "unknown",
    dependencies: {},
  };
  for (const name of ["database", "redis", "objectStorage"]) {
    const dependency = dependencies[name] || {};
    result.dependencies[name] = {
      configured: dependency.configured === true,
      ready: dependency.ready === true,
      errorPresent: Boolean(dependency.error),
    };
  }
  return result;
};

const request = http.get("http://127.0.0.1:4000/health/ready", (response) => {
  let body = "";
  response.setEncoding("utf8");
  response.on("data", (chunk) => {
    body += chunk;
    if (body.length > 65536) request.destroy();
  });
  response.on("end", () => {
    try {
      const payload = JSON.parse(body);
      console.log(JSON.stringify(summarize(payload)));
    } catch {
      console.log(JSON.stringify({ success: false, status: "unparseable", httpStatus: response.statusCode }));
    }
  });
});
request.setTimeout(5000, () => request.destroy());
request.on("error", () => {
  console.log(JSON.stringify({ success: false, status: "request_failed" }));
});
NODE
}

print_asg_diagnostics() {
  printf '\n=== ASG web-node diagnostics (no secret values) ===\n'
  printf '\n=== Docker containers ===\n'
  docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || true

  printf '\n=== Docker Compose ps ===\n'
  run_compose ps 2>/dev/null || true

  printf '\n=== Container inspect status ===\n'
  print_container_state genuine-scan-backend
  print_container_state genuine-scan-frontend

  printf '\n=== Backend readiness summary ===\n'
  print_backend_health_summary

  printf '\n=== Local health curls ===\n'
  curl -fsS -m 5 http://127.0.0.1/healthz 2>&1 || true
  printf '\n'
  curl -fsS -m 5 http://127.0.0.1/api/health/ready 2>&1 || true
  printf '\n'

  printf '\n=== Backend logs tail ===\n'
  docker logs genuine-scan-backend --tail 160 2>&1 || true
  printf '\n=== Frontend logs tail ===\n'
  docker logs genuine-scan-frontend --tail 160 2>&1 || true
  printf '\n=== End ASG web-node diagnostics ===\n'
}

printf 'Starting ASG web-node Compose mode (backend + frontend only)...\n'
if ! run_compose up -d --build --remove-orphans backend frontend; then
  print_asg_diagnostics
  die "docker compose ASG web startup failed."
fi

health_url="http://127.0.0.1/healthz"
ready_url="http://127.0.0.1/api/health/ready"
ready_json="$tmp_dir/ready.json"

printf 'Waiting for frontend health at %s...\n' "$health_url"
i=0
while :; do
  if curl -fsS "$health_url" >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  if [ "$i" -gt 40 ]; then
    print_asg_diagnostics
    die "frontend /healthz did not become healthy."
  fi
  sleep 3
done

printf 'Waiting for backend readiness through frontend path %s...\n' "$ready_url"
i=0
while :; do
  if curl -fsS "$ready_url" > "$ready_json" 2>/dev/null; then
if node --input-type=module - "$ready_json" <<'NODE'
import fs from "node:fs";
const payload = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const deps = payload.dependencies || {};
if (
  payload.success === true &&
  deps.database?.ready === true &&
  deps.redis?.configured === true &&
  deps.redis?.ready === true &&
  deps.objectStorage?.configured === true &&
  deps.objectStorage?.ready === true
) {
  process.exit(0);
}
process.exit(1);
NODE
    then
      break
    fi
  fi
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    print_asg_diagnostics
    die "backend readiness did not report database, redis, and objectStorage ready."
  fi
  sleep 3
done

printf 'ASG web-node bootstrap completed: /healthz and /api/health/ready are healthy.\n'
