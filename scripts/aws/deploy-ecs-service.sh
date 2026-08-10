#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/aws/deploy-ecs-service.sh

Update an ECS service to a new immutable image URI by cloning the current task
definition, replacing one container image, registering a new revision, and
deploying it.

Required environment:
  AWS_REGION        AWS region for ECS.
  CLUSTER_NAME      ECS cluster name.
  SERVICE_NAME      ECS service name.
  TASK_DEFINITION   Current task definition family or ARN.
  CONTAINER_NAME    Container definition name to replace.
  IMAGE_URI         Fully qualified image URI (prefer digest ref).

Optional environment:
  WAIT_FOR_STABLE   Default: true
  DRY_RUN           Default: false. When true, prints the register payload only.
  METADATA_FILE     Optional path to write deployment metadata JSON.
  VERSION_URL       Backend /version URL for post-deploy verification.
  EXPECTED_GIT_SHA  Full expected git SHA for VERSION_URL verification and runtime RELEASE_GIT_SHA.
  ENV_UPDATES       Comma-separated container env names to set. Default:
                    GIT_SHA,RELEASE_GIT_SHA when EXPECTED_GIT_SHA is set.
  GIT_SHA           Value used when ENV_UPDATES includes GIT_SHA.
  RELEASE_GIT_SHA   Value used when ENV_UPDATES includes RELEASE_GIT_SHA.
  SECRET_UPDATES_JSON
                    Optional JSON object mapping reviewed database secret names
                    to production green Secrets Manager ARNs. Backend app/preauth
                    entries are all-or-nothing.

Existing task-definition mode:
  --existing-task-definition <FULL_ARN>
  --expected-current-task-definition <FULL_ARN>
  --expected-family <family>
  --expected-image-digest <sha256:64-hex>

This explicit mode switches only to an already-registered ACTIVE revision. It
requires the release-deployer identity, performs no registration, and verifies
the exact target task definition and running task image digest before success.

Example:
  AWS_REGION=eu-west-2 \
  CLUSTER_NAME=mscqr-prod \
  SERVICE_NAME=mscqr-backend \
  TASK_DEFINITION=mscqr-backend \
  CONTAINER_NAME=backend \
  IMAGE_URI=123456789012.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:... \
  VERSION_URL=https://api.example.com/version \
  EXPECTED_GIT_SHA=$(git rev-parse HEAD) \
  ./scripts/aws/deploy-ecs-service.sh
EOF
}

EXISTING_TASK_DEFINITION_ARN="${EXISTING_TASK_DEFINITION_ARN:-}"
EXPECTED_CURRENT_TASK_DEFINITION_ARN="${EXPECTED_CURRENT_TASK_DEFINITION_ARN:-}"
EXPECTED_FAMILY="${EXPECTED_FAMILY:-}"
EXPECTED_IMAGE_DIGEST="${EXPECTED_IMAGE_DIGEST:-}"

while (($# > 0)); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --existing-task-definition)
      [[ $# -ge 2 ]] || { echo "Missing value for --existing-task-definition." >&2; exit 1; }
      EXISTING_TASK_DEFINITION_ARN="$2"
      shift 2
      ;;
    --expected-current-task-definition)
      [[ $# -ge 2 ]] || { echo "Missing value for --expected-current-task-definition." >&2; exit 1; }
      EXPECTED_CURRENT_TASK_DEFINITION_ARN="$2"
      shift 2
      ;;
    --expected-family)
      [[ $# -ge 2 ]] || { echo "Missing value for --expected-family." >&2; exit 1; }
      EXPECTED_FAMILY="$2"
      shift 2
      ;;
    --expected-image-digest)
      [[ $# -ge 2 ]] || { echo "Missing value for --expected-image-digest." >&2; exit 1; }
      EXPECTED_IMAGE_DIGEST="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -n "$EXISTING_TASK_DEFINITION_ARN" && -n "${IMAGE_URI:-}" ]]; then
  echo "IMAGE_URI must not be supplied in existing task-definition mode." >&2
  exit 1
fi

if [[ -z "$EXISTING_TASK_DEFINITION_ARN" && ( -n "$EXPECTED_CURRENT_TASK_DEFINITION_ARN" || -n "$EXPECTED_FAMILY" || -n "$EXPECTED_IMAGE_DIGEST" ) ]]; then
  echo "Existing task-definition expectations require --existing-task-definition." >&2
  exit 1
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Missing required environment variable: ${name}" >&2
    exit 1
  fi
}

if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI is required." >&2
  exit 1
fi
if ! command -v node >/dev/null 2>&1; then
  echo "node is required." >&2
  exit 1
fi

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
WAIT_FOR_STABLE="${WAIT_FOR_STABLE:-true}"
DRY_RUN="${DRY_RUN:-false}"

require_env AWS_REGION
require_env CLUSTER_NAME
require_env SERVICE_NAME
require_env CONTAINER_NAME

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION_VERIFY_SCRIPT="$REPO_ROOT/scripts/aws/verify-version-endpoint.sh"

RAW_FILE="$(mktemp)"
PAYLOAD_FILE="$(mktemp)"
EXISTING_SERVICE_FILE="$(mktemp)"
EXISTING_POST_SERVICE_FILE="$(mktemp)"
EXISTING_TASKS_LIST_FILE="$(mktemp)"
EXISTING_TASKS_RAW_FILE="$(mktemp)"
EXISTING_TASKS_FILE="$(mktemp)"
EXISTING_CALLER_FILE="$(mktemp)"
existing_mode_active=false
existing_switch_started=false

cleanup_and_rollback_on_exit() {
  local exit_code=$?
  trap - EXIT
  set +e
  if [[ "$existing_mode_active" == "true" && "$existing_switch_started" == "true" && "$exit_code" -ne 0 ]]; then
    echo "Existing task-definition switch failed; restoring ${PREVIOUS_TASK_DEFINITION_ARN}." >&2
    WAIT_FOR_STABLE=true \
      AWS_REGION="$AWS_REGION" \
      CLUSTER_NAME="$CLUSTER_NAME" \
      SERVICE_NAME="$SERVICE_NAME" \
      PREVIOUS_TASK_DEFINITION_ARN="$PREVIOUS_TASK_DEFINITION_ARN" \
      "$REPO_ROOT/scripts/aws/rollback-ecs-service.sh" || echo "Canonical rollback failed." >&2
  fi
  rm -f \
    "$RAW_FILE" \
    "$PAYLOAD_FILE" \
    "$EXISTING_SERVICE_FILE" \
    "$EXISTING_POST_SERVICE_FILE" \
    "$EXISTING_TASKS_LIST_FILE" \
    "$EXISTING_TASKS_RAW_FILE" \
    "$EXISTING_TASKS_FILE" \
    "$EXISTING_CALLER_FILE"
  exit "$exit_code"
}
trap cleanup_and_rollback_on_exit EXIT

if [[ -n "$EXISTING_TASK_DEFINITION_ARN" ]]; then
  existing_mode_active=true
  require_env CLUSTER_NAME
  require_env SERVICE_NAME
  require_env CONTAINER_NAME
  require_env EXPECTED_CURRENT_TASK_DEFINITION_ARN
  require_env EXPECTED_FAMILY
  require_env EXPECTED_IMAGE_DIGEST

  [[ "$WAIT_FOR_STABLE" == "true" ]] || {
    echo "Existing task-definition mode requires WAIT_FOR_STABLE=true." >&2
    exit 1
  }
  [[ "$DRY_RUN" == "false" ]] || {
    echo "Existing task-definition mode does not support DRY_RUN; use the offline contract tests instead." >&2
    exit 1
  }

  aws sts get-caller-identity \
    --query Arn \
    --output text \
    --no-cli-pager \
    >"$EXISTING_CALLER_FILE"

  aws ecs describe-task-definition \
    --region "$AWS_REGION" \
    --task-definition "$EXISTING_TASK_DEFINITION_ARN" \
    --include TAGS \
    >"$RAW_FILE"

  aws ecs describe-services \
    --region "$AWS_REGION" \
    --cluster "$CLUSTER_NAME" \
    --services "$SERVICE_NAME" \
    >"$EXISTING_SERVICE_FILE"

  PREVIOUS_TASK_DEFINITION_ARN="$(
    node --input-type=module - "$RAW_FILE" "$EXISTING_SERVICE_FILE" "$EXISTING_CALLER_FILE" "$AWS_REGION" "$EXISTING_TASK_DEFINITION_ARN" "$EXPECTED_CURRENT_TASK_DEFINITION_ARN" "$EXPECTED_FAMILY" "$EXPECTED_IMAGE_DIGEST" "$CONTAINER_NAME" "${EXPECTED_GIT_SHA:-}" <<'NODE'
import fs from "node:fs";

const [targetPath, servicePath, callerPath, region, targetArn, expectedCurrentArn, expectedFamily, expectedDigest, containerName, expectedGitSha] = process.argv.slice(2);
const targetResponse = JSON.parse(fs.readFileSync(targetPath, "utf8"));
const serviceResponse = JSON.parse(fs.readFileSync(servicePath, "utf8"));
const callerArn = fs.readFileSync(callerPath, "utf8").trim();
const accountId = "368992683803";
const arnPattern = /^arn:aws:ecs:([a-z0-9-]+):([0-9]{12}):task-definition\/([A-Za-z0-9_-]+):([1-9][0-9]*)$/;
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const fail = (message) => { throw new Error(message); };

const targetMatch = arnPattern.exec(targetArn);
const currentMatch = arnPattern.exec(expectedCurrentArn);
if (!targetMatch) fail("Existing task-definition target must be a full ARN with an exact revision.");
if (!currentMatch) fail("Expected current task definition must be a full ARN with an exact revision.");
if (targetMatch[1] !== region || currentMatch[1] !== region) fail("Task-definition ARN region does not match AWS_REGION.");
if (targetMatch[2] !== accountId || currentMatch[2] !== accountId) fail("Task-definition ARN account is outside the production contract.");
if (!digestPattern.test(expectedDigest)) fail("Expected image digest must be sha256 followed by 64 lowercase hex characters.");
if (!/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/.test(callerArn)) fail("Existing task-definition mode requires the production release-deployer identity.");

const target = targetResponse.taskDefinition;
if (!target || target.taskDefinitionArn !== targetArn) fail("Described task definition did not match the exact requested ARN.");
if (target.status !== "ACTIVE") fail(`Target task definition status is ${target.status || "missing"}; expected ACTIVE.`);
if (target.family !== expectedFamily || targetMatch[3] !== expectedFamily) fail("Target task-definition family does not match the expected family.");
const runtimePlatform = target.runtimePlatform || null;
if (runtimePlatform?.cpuArchitecture && runtimePlatform.cpuArchitecture !== "X86_64") fail(`Target runtimePlatform.cpuArchitecture is ${runtimePlatform.cpuArchitecture}; expected X86_64.`);
const containers = Array.isArray(target.containerDefinitions) ? target.containerDefinitions : [];
const selected = containers.filter((container) => container?.name === containerName);
if (selected.length !== 1) fail(`Target task definition must contain exactly one ${containerName} container.`);
const imageMatch = /@(?<digest>sha256:[a-f0-9]{64})$/.exec(selected[0].image || "");
if (!imageMatch || imageMatch.groups.digest !== expectedDigest) fail("Target container image digest does not match the approved digest.");
const metadata = new Map((selected[0].environment || []).filter((entry) => entry?.name).map((entry) => [entry.name, entry.value]));
const sourceMetadata = ["GIT_SHA", "RELEASE_GIT_SHA"].filter((name) => metadata.has(name));
if (sourceMetadata.length > 0 && (!expectedGitSha || !/^[0-9a-f]{40}$/.test(expectedGitSha))) fail("Target source metadata is present but EXPECTED_GIT_SHA is missing or malformed.");
for (const name of sourceMetadata) if (metadata.get(name) !== expectedGitSha) fail(`Target ${name} does not match EXPECTED_GIT_SHA.`);

if (!Array.isArray(serviceResponse.failures) || serviceResponse.failures.length !== 0) fail("ECS service description returned failures.");
const services = Array.isArray(serviceResponse.services) ? serviceResponse.services : [];
if (services.length !== 1) fail("ECS service description did not return exactly one service.");
const service = services[0];
if (service.status !== "ACTIVE") fail(`ECS service status is ${service.status || "missing"}; expected ACTIVE.`);
if (service.taskDefinition !== expectedCurrentArn) fail("ECS service is not bound to the expected current task definition.");
if (!Number.isInteger(service.desiredCount) || service.desiredCount < 1) fail("ECS service desired count is invalid.");
const deployments = Array.isArray(service.deployments) ? service.deployments : [];
if (deployments.length !== 1 || deployments[0]?.status !== "PRIMARY" || deployments[0]?.taskDefinition !== expectedCurrentArn || deployments[0]?.pendingCount !== 0 || deployments[0]?.runningCount !== service.desiredCount || (deployments[0]?.rolloutState && deployments[0].rolloutState !== "COMPLETED")) fail("ECS service has a concurrent or unhealthy deployment.");

process.stdout.write(expectedCurrentArn);
NODE
  )"

  if [[ "$PREVIOUS_TASK_DEFINITION_ARN" != "$EXISTING_TASK_DEFINITION_ARN" ]]; then
    aws ecs update-service \
      --region "$AWS_REGION" \
      --cluster "$CLUSTER_NAME" \
      --service "$SERVICE_NAME" \
      --task-definition "$EXISTING_TASK_DEFINITION_ARN" \
      >/dev/null
    existing_switch_started=true
  else
    echo "Target task definition is already active on ${SERVICE_NAME}; no service update required."
  fi

  aws ecs wait services-stable \
    --region "$AWS_REGION" \
    --cluster "$CLUSTER_NAME" \
    --services "$SERVICE_NAME"

  aws ecs describe-services \
    --region "$AWS_REGION" \
    --cluster "$CLUSTER_NAME" \
    --services "$SERVICE_NAME" \
    >"$EXISTING_POST_SERVICE_FILE"

  node --input-type=module - "$EXISTING_POST_SERVICE_FILE" "$EXISTING_TASKS_LIST_FILE" "$EXISTING_TASK_DEFINITION_ARN" <<'NODE'
import fs from "node:fs";
const [servicePath, taskListPath, targetArn] = process.argv.slice(2);
const response = JSON.parse(fs.readFileSync(servicePath, "utf8"));
const fail = (message) => { throw new Error(message); };
if (!Array.isArray(response.failures) || response.failures.length !== 0) fail("Post-switch ECS service description returned failures.");
if (response.services?.length !== 1) fail("Post-switch ECS service description did not return exactly one service.");
const service = response.services[0];
if (service.status !== "ACTIVE" || service.taskDefinition !== targetArn) fail("Post-switch service is not bound to the exact target task definition.");
const deployments = Array.isArray(service.deployments) ? service.deployments : [];
if (deployments.length !== 1 || deployments[0]?.status !== "PRIMARY" || deployments[0]?.taskDefinition !== targetArn || deployments[0]?.pendingCount !== 0 || deployments[0]?.runningCount !== service.desiredCount || (deployments[0]?.rolloutState && deployments[0].rolloutState !== "COMPLETED")) fail("Post-switch ECS service is not stable on the exact target.");
fs.writeFileSync(taskListPath, JSON.stringify({ targetArn, desiredCount: service.desiredCount }));
NODE

  aws ecs list-tasks \
    --region "$AWS_REGION" \
    --cluster "$CLUSTER_NAME" \
    --service-name "$SERVICE_NAME" \
    --desired-status RUNNING \
    >"$EXISTING_TASKS_RAW_FILE"

  running_task_arns=()
  while IFS= read -r task_arn; do
    [[ -n "$task_arn" ]] && running_task_arns+=("$task_arn")
  done < <(node --input-type=module - "$EXISTING_TASKS_RAW_FILE" <<'NODE'
import fs from "node:fs";
const response = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
if (!response || typeof response !== "object" || Array.isArray(response)) throw new Error("ECS list-tasks response must be an object.");
if (!Object.hasOwn(response, "taskArns") || !Array.isArray(response.taskArns)) throw new Error("ECS list-tasks response must contain an array taskArns field.");
if (Object.hasOwn(response, "nextToken") && typeof response.nextToken !== "string") throw new Error("ECS list-tasks nextToken must be a string when present.");
if (typeof response.nextToken === "string" && response.nextToken.length > 0) throw new Error("ECS list-tasks pagination is not supported; nextToken was returned.");
const taskArnPattern = /^arn:aws:ecs:[a-z0-9-]+:[0-9]{12}:task\/[^/]+\/[^/]+$/;
for (const arn of response.taskArns) {
  if (typeof arn !== "string" || arn.length === 0 || !taskArnPattern.test(arn)) throw new Error("ECS list-tasks returned a malformed task ARN.");
  process.stdout.write(`${arn}\n`);
}
NODE
  )
  [[ "${#running_task_arns[@]}" -gt 0 ]] || { echo "No running ECS tasks were returned after the existing task-definition switch." >&2; exit 1; }

  aws ecs describe-tasks \
    --region "$AWS_REGION" \
    --cluster "$CLUSTER_NAME" \
    --tasks "${running_task_arns[@]}" \
    >"$EXISTING_TASKS_FILE"

  node --input-type=module - "$EXISTING_POST_SERVICE_FILE" "$EXISTING_TASKS_LIST_FILE" "$EXISTING_TASKS_FILE" "$EXISTING_TASK_DEFINITION_ARN" "$EXPECTED_IMAGE_DIGEST" "$CONTAINER_NAME" <<'NODE'
import fs from "node:fs";
const [servicePath, taskListPath, tasksPath, targetArn, expectedDigest, containerName] = process.argv.slice(2);
const serviceResponse = JSON.parse(fs.readFileSync(servicePath, "utf8"));
const taskSummary = JSON.parse(fs.readFileSync(taskListPath, "utf8"));
const tasksResponse = JSON.parse(fs.readFileSync(tasksPath, "utf8"));
const fail = (message) => { throw new Error(message); };
const desiredCount = serviceResponse.services?.[0]?.desiredCount;
if (taskSummary.targetArn !== targetArn || taskSummary.desiredCount !== desiredCount) fail("Post-switch task summary binding is inconsistent.");
if (!Array.isArray(tasksResponse.failures) || tasksResponse.failures.length !== 0) fail("ECS describe-tasks returned failures.");
if (!Array.isArray(tasksResponse.tasks) || tasksResponse.tasks.length !== desiredCount) fail("Running task count does not equal the desired count.");
for (const task of tasksResponse.tasks) {
  if (task.lastStatus !== "RUNNING" || task.taskDefinitionArn !== targetArn) fail("A running task is not using the exact target task definition.");
  const containers = (task.containers || []).filter((container) => container?.name === containerName);
  if (containers.length !== 1 || containers[0].imageDigest !== expectedDigest) fail("A running target container does not report the approved image digest.");
}
NODE

  if [[ -n "${METADATA_FILE:-}" ]]; then
    node --input-type=module - "$METADATA_FILE" "$CLUSTER_NAME" "$SERVICE_NAME" "$CONTAINER_NAME" "$PREVIOUS_TASK_DEFINITION_ARN" "$EXISTING_TASK_DEFINITION_ARN" "$EXPECTED_IMAGE_DIGEST" <<'NODE'
import fs from "node:fs";
const [outPath, clusterName, serviceName, containerName, previousTaskDefinitionArn, targetTaskDefinitionArn, expectedImageDigest] = process.argv.slice(2);
fs.writeFileSync(outPath, JSON.stringify({ mode: "existing-task-definition", clusterName, serviceName, containerName, previousTaskDefinitionArn, targetTaskDefinitionArn, expectedImageDigest }, null, 2));
NODE
  fi

  existing_switch_started=false
  echo "Verified ${SERVICE_NAME} on ${CLUSTER_NAME} using existing task definition ${EXISTING_TASK_DEFINITION_ARN}"
  exit 0
fi

require_env TASK_DEFINITION
require_env IMAGE_URI

aws ecs describe-task-definition \
  --region "$AWS_REGION" \
  --task-definition "$TASK_DEFINITION" \
  --include TAGS \
  >"$RAW_FILE"

ENV_UPDATES="${ENV_UPDATES:-}"
if [[ -z "$ENV_UPDATES" && -n "${EXPECTED_GIT_SHA:-}" ]]; then
  ENV_UPDATES="GIT_SHA,RELEASE_GIT_SHA"
fi
GIT_SHA="${GIT_SHA:-${EXPECTED_GIT_SHA:-}}"
RELEASE_GIT_SHA="${RELEASE_GIT_SHA:-${EXPECTED_GIT_SHA:-}}"

node --input-type=module - "$RAW_FILE" "$PAYLOAD_FILE" "$CONTAINER_NAME" "$IMAGE_URI" "$ENV_UPDATES" "$GIT_SHA" "$RELEASE_GIT_SHA" "${SECRET_UPDATES_JSON:-{}}" <<'NODE'
import fs from "node:fs";

const [rawPath, payloadPath, containerName, imageUri, envUpdatesText, gitSha, releaseGitSha, secretUpdatesText] = process.argv.slice(2);
const raw = JSON.parse(fs.readFileSync(rawPath, "utf8"));
const taskDefinition = raw.taskDefinition;

if (!taskDefinition) {
  throw new Error("ECS describe-task-definition response did not include taskDefinition.");
}

let containerFound = false;
const envValues = new Map([
  ["GIT_SHA", gitSha],
  ["RELEASE_GIT_SHA", releaseGitSha],
]);
const envUpdates = envUpdatesText
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);
const secretUpdates = JSON.parse(secretUpdatesText);
const allowedSecretNames = new Set([
  "DATABASE_URL",
  "AUTHENTICATED_APP_DATABASE_URL",
  "PREAUTH_DATABASE_URL",
  "MSCQR_C03_PREAUTH_DATABASE_URL",
]);
if (!secretUpdates || typeof secretUpdates !== "object" || Array.isArray(secretUpdates)
    || Object.keys(secretUpdates).some((name) => !allowedSecretNames.has(name))
    || Object.values(secretUpdates).some((arn) => !/^arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr\/production\/rls-green\/phase2\/database-url\/(app|preauth|worker|scheduled)-[A-Za-z0-9]{6}$/.test(arn))) {
  throw new Error("SECRET_UPDATES_JSON is outside the reviewed production green database contract.");
}
const backendRestrictedNames = ["DATABASE_URL", "AUTHENTICATED_APP_DATABASE_URL", "PREAUTH_DATABASE_URL"];
const configuredBackendRestricted = backendRestrictedNames.filter((name) => Object.hasOwn(secretUpdates, name));
const workerOnly = configuredBackendRestricted.length === 1
  && configuredBackendRestricted[0] === "DATABASE_URL"
  && /\/worker-[A-Za-z0-9]{6}$/.test(secretUpdates.DATABASE_URL);
if (configuredBackendRestricted.length > 0 && configuredBackendRestricted.length !== backendRestrictedNames.length && !workerOnly) {
  throw new Error("Production backend database secrets must be updated together.");
}

for (const envName of envUpdates) {
  if (!envValues.has(envName)) {
    throw new Error(`Unsupported ENV_UPDATES entry: ${envName}. Supported: GIT_SHA, RELEASE_GIT_SHA.`);
  }
  if (!envValues.get(envName)) {
    throw new Error(`ENV_UPDATES requested ${envName}, but no value was provided for it.`);
  }
}

const containerDefinitions = (taskDefinition.containerDefinitions || []).map((container) => {
  if (container.name !== containerName) return container;
  containerFound = true;
  const environment = Array.isArray(container.environment)
    ? container.environment.filter((entry) => !envUpdates.includes(entry?.name))
    : [];
  for (const envName of envUpdates) {
    environment.push({ name: envName, value: envValues.get(envName) });
  }
  const secrets = [
    ...(Array.isArray(container.secrets) ? container.secrets : []).filter((entry) => !Object.hasOwn(secretUpdates, entry?.name)),
    ...Object.entries(secretUpdates).map(([name, valueFrom]) => ({ name, valueFrom })),
  ];
  return { ...container, image: imageUri, environment, secrets };
});

if (!containerFound) {
  throw new Error(`Container ${containerName} was not found in task definition ${taskDefinition.family}.`);
}

const runtimePlatform = taskDefinition.runtimePlatform || null;
if (runtimePlatform?.cpuArchitecture && runtimePlatform.cpuArchitecture !== "X86_64") {
  throw new Error(
    `Refusing to deploy: task definition runtimePlatform.cpuArchitecture is ${runtimePlatform.cpuArchitecture}, expected X86_64.`
  );
}

const payload = {
  family: taskDefinition.family,
  taskRoleArn: taskDefinition.taskRoleArn,
  executionRoleArn: taskDefinition.executionRoleArn,
  networkMode: taskDefinition.networkMode,
  containerDefinitions,
  volumes: taskDefinition.volumes,
  placementConstraints: taskDefinition.placementConstraints,
  requiresCompatibilities: taskDefinition.requiresCompatibilities,
  cpu: taskDefinition.cpu,
  memory: taskDefinition.memory,
};

if (Array.isArray(raw.tags) && raw.tags.length > 0) {
  payload.tags = raw.tags;
}

for (const optionalField of [
  "pidMode",
  "ipcMode",
  "proxyConfiguration",
  "inferenceAccelerators",
  "ephemeralStorage",
  "runtimePlatform",
]) {
  if (taskDefinition[optionalField] != null) {
    payload[optionalField] = taskDefinition[optionalField];
  }
}

fs.writeFileSync(payloadPath, JSON.stringify(payload, null, 2));
NODE

PREVIOUS_TASK_DEFINITION_ARN="$(
  node --input-type=module -e 'import fs from "node:fs"; const raw = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); process.stdout.write(raw.taskDefinition.taskDefinitionArn || "");' "$RAW_FILE"
)"

if [[ "$DRY_RUN" == "true" ]]; then
  cat "$PAYLOAD_FILE"
  exit 0
fi

NEW_TASK_DEFINITION_ARN="$(
  aws ecs register-task-definition \
    --region "$AWS_REGION" \
    --cli-input-json "file://${PAYLOAD_FILE}" \
    --query 'taskDefinition.taskDefinitionArn' \
    --output text
)"

aws ecs update-service \
  --region "$AWS_REGION" \
  --cluster "$CLUSTER_NAME" \
  --service "$SERVICE_NAME" \
  --task-definition "$NEW_TASK_DEFINITION_ARN" \
  >/dev/null

if [[ -n "${METADATA_FILE:-}" ]]; then
  node --input-type=module - "$METADATA_FILE" "$CLUSTER_NAME" "$SERVICE_NAME" "$CONTAINER_NAME" "$IMAGE_URI" "$PREVIOUS_TASK_DEFINITION_ARN" "$NEW_TASK_DEFINITION_ARN" <<'NODE'
import fs from "node:fs";

const [outPath, clusterName, serviceName, containerName, imageUri, previousTaskDefinitionArn, newTaskDefinitionArn] =
  process.argv.slice(2);
const payload = {
  clusterName,
  serviceName,
  containerName,
  imageUri,
  previousTaskDefinitionArn,
  newTaskDefinitionArn,
};
fs.writeFileSync(outPath, JSON.stringify(payload, null, 2));
NODE
fi

if [[ "$WAIT_FOR_STABLE" == "true" ]]; then
  aws ecs wait services-stable \
    --region "$AWS_REGION" \
    --cluster "$CLUSTER_NAME" \
    --services "$SERVICE_NAME"
fi

echo "Deployed ${SERVICE_NAME} on ${CLUSTER_NAME}"
echo "  Task definition: ${NEW_TASK_DEFINITION_ARN}"
echo "  Container: ${CONTAINER_NAME}"
echo "  Image: ${IMAGE_URI}"

if [[ -n "${VERSION_URL:-}" || -n "${EXPECTED_GIT_SHA:-}" ]]; then
  require_env VERSION_URL
  require_env EXPECTED_GIT_SHA
  "$VERSION_VERIFY_SCRIPT" "$VERSION_URL" "$EXPECTED_GIT_SHA"
fi
