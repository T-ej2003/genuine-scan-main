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
  EXPECTED_GIT_SHA  Full expected git SHA for VERSION_URL verification.

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
require_env TASK_DEFINITION
require_env CONTAINER_NAME
require_env IMAGE_URI

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION_VERIFY_SCRIPT="$REPO_ROOT/scripts/aws/verify-version-endpoint.sh"

RAW_FILE="$(mktemp)"
PAYLOAD_FILE="$(mktemp)"
trap 'rm -f "$RAW_FILE" "$PAYLOAD_FILE"' EXIT

aws ecs describe-task-definition \
  --region "$AWS_REGION" \
  --task-definition "$TASK_DEFINITION" \
  --include TAGS \
  >"$RAW_FILE"

node --input-type=module - "$RAW_FILE" "$PAYLOAD_FILE" "$CONTAINER_NAME" "$IMAGE_URI" <<'NODE'
import fs from "node:fs";

const [rawPath, payloadPath, containerName, imageUri] = process.argv.slice(2);
const raw = JSON.parse(fs.readFileSync(rawPath, "utf8"));
const taskDefinition = raw.taskDefinition;

if (!taskDefinition) {
  throw new Error("ECS describe-task-definition response did not include taskDefinition.");
}

let containerFound = false;
const containerDefinitions = (taskDefinition.containerDefinitions || []).map((container) => {
  if (container.name !== containerName) return container;
  containerFound = true;
  return { ...container, image: imageUri };
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
  tags: raw.tags || [],
};

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
