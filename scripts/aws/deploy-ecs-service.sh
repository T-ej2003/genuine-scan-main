#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

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
  ENABLE_EXECUTE_COMMAND
                    Default: false. When true, the canonical service update enables ECS Exec.
  PROPAGATE_TAGS     Optional. Existing-task-definition mode accepts only TASK_DEFINITION;
                    used by governed rotation to propagate the reviewed task identity tag.
  METADATA_FILE     Optional path to write deployment metadata JSON.
  VERSION_URL       Backend /version URL for post-deploy verification.
  EXPECTED_GIT_SHA  Full expected git SHA for VERSION_URL verification and runtime RELEASE_GIT_SHA.
  OVERLAP_READINESS_EVIDENCE_FILE
                    Mode-0600 redacted readiness evidence required before an existing-task-definition switch.
  OVERLAP_READINESS_EVIDENCE_SHA256
                    SHA-256 of OVERLAP_READINESS_EVIDENCE_FILE.
  ROTATION_ID       Exact governed rotation ID bound to readiness evidence.
  ROTATION_STATE_SHA256
                    SHA-256 of the persisted redacted rotation state bound to readiness evidence.
  DEPLOYMENT_SOURCE_SHA
                    Exact protected-main source SHA bound to readiness evidence.
  MSCQR_EXISTING_TASK_DEPLOYMENT_MODE
                    rotation (default) or normal-stage-b. Normal mode is accepted
                    only from the live-state normal activation coordinator.
  NORMAL_ACTIVATION_BINDING_FILE
                    Mode-0600 state/live-policy binding created by the normal activation coordinator.
  NORMAL_ACTIVATION_BINDING_SHA256
                    SHA-256 of NORMAL_ACTIVATION_BINDING_FILE.
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
the exact target task definition, service load-balancer port binding, and running
task image digest before success.

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

if [[ -n "${PROPAGATE_TAGS:-}" && "${PROPAGATE_TAGS}" != "TASK_DEFINITION" ]]; then
  echo "PROPAGATE_TAGS must be TASK_DEFINITION when provided." >&2
  exit 1
fi
if [[ -n "${PROPAGATE_TAGS:-}" && -z "$EXISTING_TASK_DEFINITION_ARN" ]]; then
  echo "PROPAGATE_TAGS is supported only in existing task-definition mode." >&2
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

require_version_verification_inputs() {
  if [[ -n "${VERSION_URL:-}" || -n "${EXPECTED_GIT_SHA:-}" ]]; then
    require_env VERSION_URL
    require_env EXPECTED_GIT_SHA
  fi
}

require_existing_activation_authorization() {
  if [[ -z "$EXISTING_TASK_DEFINITION_ARN" ]]; then return; fi
  if [[ "${MSCQR_GOVERNED_ORCHESTRATOR:-}" != "1" ]]; then
    echo "Existing task-definition deployment must be invoked by run-production-cutover.mjs or production-normal-backend-activation.mjs." >&2
    exit 1
  fi
  if [[ "${MSCQR_EXISTING_TASK_DEPLOYMENT_MODE:-rotation}" == "normal-stage-b" ]]; then
    require_env NORMAL_ACTIVATION_BINDING_FILE
    require_env NORMAL_ACTIVATION_BINDING_SHA256
    node --input-type=module - "$NORMAL_ACTIVATION_BINDING_FILE" "$NORMAL_ACTIVATION_BINDING_SHA256" "$EXISTING_TASK_DEFINITION_ARN" "$EXPECTED_CURRENT_TASK_DEFINITION_ARN" "$EXPECTED_IMAGE_DIGEST" "${EXPECTED_GIT_SHA:-}" <<'NODE'
import crypto from "node:crypto";
import fs from "node:fs";
const [file, expectedSha, targetArn, currentArn, digest, sourceSha] = process.argv.slice(2);
const bytes = fs.readFileSync(file);
if (crypto.createHash("sha256").update(bytes).digest("hex") !== expectedSha) throw new Error("Normal activation binding changed before the existing-task switch.");
const value = JSON.parse(bytes);
const sourcePattern = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/(mscqr-backend|mscqr-production-rls-green-backend-candidate):[1-9][0-9]*$/;
if (value.schemaVersion !== 2 || value.releaseMode !== "normal" || value.targetArn !== targetArn || value.sourceArn !== currentArn || value.expectedCurrentTaskDefinitionArn !== currentArn || value.digest !== digest || !/^sha256:[a-f0-9]{64}$/.test(value.sourceDigest || "") || value.rollbackImageVerified !== true || !sourcePattern.test(value.sourceArn || "") || !Number.isInteger(value.desiredCount) || value.desiredCount < 1 || value.sourceSha !== sourceSha || value.clusterArn !== "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main" || value.serviceArn !== "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2") throw new Error("Normal activation binding does not match the exact SOURCE/TARGET switch inputs.");
NODE
    return
  fi
  [[ "${MSCQR_EXISTING_TASK_DEPLOYMENT_MODE:-rotation}" == "rotation" ]] || { echo "Unsupported existing task-definition deployment mode." >&2; exit 1; }
  require_env OVERLAP_READINESS_EVIDENCE_FILE
  require_env OVERLAP_READINESS_EVIDENCE_SHA256
  require_env ROTATION_ID
  require_env ROTATION_STATE_SHA256
  require_env DEPLOYMENT_SOURCE_SHA
  node "$SCRIPT_DIR/production-overlap-readiness-contract.mjs" \
    --mode rotation-overlap \
    --evidence-file "$OVERLAP_READINESS_EVIDENCE_FILE" \
    --evidence-sha256 "$OVERLAP_READINESS_EVIDENCE_SHA256" \
    --source-sha "$DEPLOYMENT_SOURCE_SHA" \
    --rotation-id "$ROTATION_ID" \
    --rotation-state-sha256 "$ROTATION_STATE_SHA256" >/dev/null
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
ENABLE_EXECUTE_COMMAND="${ENABLE_EXECUTE_COMMAND:-false}"

case "$ENABLE_EXECUTE_COMMAND" in
  true|false) ;;
  *) echo "ENABLE_EXECUTE_COMMAND must be true or false." >&2; exit 1 ;;
esac

require_env AWS_REGION
require_env CLUSTER_NAME
require_env SERVICE_NAME
require_env CONTAINER_NAME

reject_generic_stage_b_registration() {
  local family="${TASK_DEFINITION:-}"
  family="${family##*/}"
  family="${family%%:*}"
  case "$family" in
    mscqr-production-rls-green-backend-candidate|mscqr-production-rls-green-worker-candidate|mscqr-production-full-rls-green-application-canary|mscqr-production-full-rls-green-read-only-canary|mscqr-production-full-rls-green-*)
      echo "Stage-B managed task-definition families must be registered by Terraform or the governed rotation producer, not deploy-ecs-service.sh." >&2
      exit 1
      ;;
  esac
}

if [[ -z "$EXISTING_TASK_DEFINITION_ARN" ]]; then
  reject_generic_stage_b_registration
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION_VERIFY_SCRIPT="$REPO_ROOT/scripts/aws/verify-version-endpoint.sh"

verify_deployed_version_if_requested() {
  require_version_verification_inputs
  if [[ -n "${VERSION_URL:-}" || -n "${EXPECTED_GIT_SHA:-}" ]]; then
    "$VERSION_VERIFY_SCRIPT" "$VERSION_URL" "$EXPECTED_GIT_SHA"
  fi
}

validate_service_load_balancer_compatibility() {
  local service_path="$1"
  local task_definition_path="$2"
  node --input-type=module - "$service_path" "$task_definition_path" "$CONTAINER_NAME" <<'NODE'
import fs from "node:fs";

const [servicePath, taskDefinitionPath, expectedContainerName] = process.argv.slice(2);
const serviceResponse = JSON.parse(fs.readFileSync(servicePath, "utf8"));
const taskResponse = JSON.parse(fs.readFileSync(taskDefinitionPath, "utf8"));
const fail = (message) => { throw new Error(`ECS service/task-definition compatibility failed: ${message}`); };
if (!Array.isArray(serviceResponse.failures) || serviceResponse.failures.length !== 0 || serviceResponse.services?.length !== 1) fail("service response is malformed.");
const service = serviceResponse.services[0];
if (!Array.isArray(service.loadBalancers) || service.loadBalancers.length === 0) fail("service load-balancer contract is missing.");
const definition = taskResponse.taskDefinition || taskResponse;
const containers = Array.isArray(definition.containerDefinitions) ? definition.containerDefinitions : [];
for (const loadBalancer of service.loadBalancers) {
  if (typeof loadBalancer.containerName !== "string" || loadBalancer.containerName !== expectedContainerName || !Number.isInteger(loadBalancer.containerPort)) fail("service load-balancer binding is malformed or names a different container.");
  const matches = containers.filter((container) => container?.name === loadBalancer.containerName);
  if (matches.length !== 1) fail(`candidate must expose exactly one ${loadBalancer.containerName} container.`);
  const mappings = Array.isArray(matches[0].portMappings) ? matches[0].portMappings : [];
  const compatible = mappings.filter((mapping) => mapping?.containerPort === loadBalancer.containerPort);
  if (compatible.length !== 1) fail(`${loadBalancer.containerName}:${loadBalancer.containerPort} is not exposed exactly once.`);
  const mapping = compatible[0];
  if (!Number.isInteger(mapping.hostPort) || mapping.hostPort !== mapping.containerPort || mapping.protocol !== "tcp" || (mapping.appProtocol !== undefined && mapping.appProtocol !== "http")) fail(`${loadBalancer.containerName}:${loadBalancer.containerPort} has an incompatible port mapping.`);
}
NODE
}

RAW_FILE="$(mktemp)"
PAYLOAD_FILE="$(mktemp)"
EXISTING_SERVICE_FILE="$(mktemp)"
EXISTING_POST_SERVICE_FILE="$(mktemp)"
EXISTING_TASKS_LIST_FILE="$(mktemp)"
EXISTING_TASKS_RAW_FILE="$(mktemp)"
EXISTING_TASKS_FILE="$(mktemp)"
EXISTING_CALLER_FILE="$(mktemp)"
ROLLBACK_TASK_DEFINITION_FILE="$(mktemp)"
ROLLBACK_IMAGE_FILE="$(mktemp)"
existing_mode_active=false
existing_switch_started=false
update_attempted=false
update_state="NOT_ATTEMPTED"
rollback_result="NOT_REQUIRED"
UPDATE_SETTLEMENT_ATTEMPTS=6
UPDATE_SETTLEMENT_INTERVAL_SECONDS=2

settle_update_outcome() {
  local attempt classification
  local saw_previous=false
  settlement_result="UNKNOWN"
  for ((attempt = 1; attempt <= UPDATE_SETTLEMENT_ATTEMPTS; attempt++)); do
    if ! aws ecs describe-services \
      --region "$AWS_REGION" \
      --cluster "$CLUSTER_NAME" \
      --services "$SERVICE_NAME" \
      >"$EXISTING_POST_SERVICE_FILE"; then
      if ((attempt < UPDATE_SETTLEMENT_ATTEMPTS)); then
        if ! sleep "$UPDATE_SETTLEMENT_INTERVAL_SECONDS"; then settlement_result="UNKNOWN"; return 0; fi
      fi
      continue
    fi
    if ! classification="$(node --input-type=module - "$EXISTING_POST_SERVICE_FILE" "$PREVIOUS_TASK_DEFINITION_ARN" "$EXISTING_TASK_DEFINITION_ARN" <<'NODE'
import fs from "node:fs";

const [responsePath, previousArn, targetArn] = process.argv.slice(2);
const response = JSON.parse(fs.readFileSync(responsePath, "utf8"));
if (!Array.isArray(response.failures) || response.failures.length !== 0 || response.services?.length !== 1) throw new Error("ECS service settlement response is malformed.");
const service = response.services[0];
const deployments = service.deployments;
if (typeof service.taskDefinition !== "string" || !Array.isArray(deployments) || deployments.length === 0 || deployments.some(({ taskDefinition }) => typeof taskDefinition !== "string")) throw new Error("ECS service settlement response is incomplete.");
if (service.taskDefinition === targetArn || deployments.some(({ taskDefinition }) => taskDefinition === targetArn)) {
  process.stdout.write("TARGET");
} else if (service.taskDefinition !== previousArn || deployments.some(({ taskDefinition }) => taskDefinition !== previousArn)) {
  process.stdout.write("FOREIGN");
} else {
  const deployment = deployments.length === 1 ? deployments[0] : null;
  const stable = deployment?.status === "PRIMARY"
    && deployment.pendingCount === 0
    && deployment.runningCount === service.desiredCount
    && (!deployment.rolloutState || deployment.rolloutState === "COMPLETED");
  process.stdout.write(stable ? "PREVIOUS_STABLE" : "PREVIOUS_PENDING");
}
NODE
)"; then
      if ((attempt < UPDATE_SETTLEMENT_ATTEMPTS)); then
        if ! sleep "$UPDATE_SETTLEMENT_INTERVAL_SECONDS"; then settlement_result="UNKNOWN"; return 0; fi
      fi
      continue
    fi
    case "$classification" in
      TARGET)
        settlement_result="TARGET"
        return 0
        ;;
      FOREIGN)
        settlement_result="FOREIGN"
        return 0
        ;;
      PREVIOUS_STABLE|PREVIOUS_PENDING)
        saw_previous=true
        ;;
      *)
        settlement_result="UNKNOWN"
        return 0
        ;;
    esac
    if ((attempt < UPDATE_SETTLEMENT_ATTEMPTS)); then
      if ! sleep "$UPDATE_SETTLEMENT_INTERVAL_SECONDS"; then
        settlement_result="UNKNOWN"
        return 0
      fi
    fi
  done
  if [[ "$saw_previous" == "true" ]]; then
    settlement_result="AMBIGUOUS"
  else
    settlement_result="UNKNOWN"
  fi
}

verify_existing_service_restored() {
  local response_file="$EXISTING_POST_SERVICE_FILE"
  if ! aws ecs describe-services \
    --region "$AWS_REGION" \
    --cluster "$CLUSTER_NAME" \
    --services "$SERVICE_NAME" \
    >"$response_file"; then
    echo "UNKNOWN_SERVICE_STATE: rollback completed without a verifiable service description." >&2
    return 1
  fi
  node --input-type=module - "$response_file" "$PREVIOUS_TASK_DEFINITION_ARN" <<'NODE'
import fs from "node:fs";
const [responsePath, previousArn] = process.argv.slice(2);
const response = JSON.parse(fs.readFileSync(responsePath, "utf8"));
const service = response.services?.length === 1 ? response.services[0] : null;
const deployment = service?.deployments?.length === 1 ? service.deployments[0] : null;
if (!Array.isArray(response.failures) || response.failures.length !== 0 || !service || service.status !== "ACTIVE" || service.taskDefinition !== previousArn || !deployment || deployment.status !== "PRIMARY" || deployment.taskDefinition !== previousArn || deployment.pendingCount !== 0 || deployment.runningCount !== service.desiredCount || (deployment.rolloutState && deployment.rolloutState !== "COMPLETED")) {
  throw new Error("Rollback did not restore the exact previous stable task definition.");
}
NODE
}

classify_rollback_ownership() {
  rollback_ownership="UNKNOWN"
  if ! aws ecs describe-services \
    --region "$AWS_REGION" \
    --cluster "$CLUSTER_NAME" \
    --services "$SERVICE_NAME" \
    >"$EXISTING_POST_SERVICE_FILE"; then
    return 0
  fi
  if ! rollback_ownership="$(node --input-type=module - "$EXISTING_POST_SERVICE_FILE" "$PREVIOUS_TASK_DEFINITION_ARN" "$EXISTING_TASK_DEFINITION_ARN" <<'NODE'
import fs from "node:fs";

const [responsePath, previousArn, targetArn] = process.argv.slice(2);
const response = JSON.parse(fs.readFileSync(responsePath, "utf8"));
const fail = (message) => { throw new Error(message); };
if (!Array.isArray(response.failures) || response.failures.length !== 0 || response.services?.length !== 1) fail("ECS rollback ownership response is malformed.");
const service = response.services[0];
const deployments = service.deployments;
if (typeof service.taskDefinition !== "string" || !Array.isArray(deployments) || deployments.length === 0 || deployments.some(({ taskDefinition }) => typeof taskDefinition !== "string")) fail("ECS rollback ownership response is incomplete.");
const taskDefinitions = [service.taskDefinition, ...deployments.map(({ taskDefinition }) => taskDefinition)];
if (taskDefinitions.some((taskDefinition) => taskDefinition !== previousArn && taskDefinition !== targetArn)) {
  process.stdout.write("FOREIGN");
} else if (taskDefinitions.includes(targetArn)) {
  process.stdout.write("TARGET_OWNED");
} else if (service.taskDefinition === previousArn && taskDefinitions.every((taskDefinition) => taskDefinition === previousArn)) {
  process.stdout.write("PREVIOUS_RESTORED");
} else {
  process.stdout.write("UNKNOWN");
}
NODE
)"; then
    rollback_ownership="UNKNOWN"
  fi
}

cleanup_and_rollback_on_exit() {
  local exit_code=$?
  trap - EXIT
  set +e
  if [[ "$existing_mode_active" == "true" && "$update_attempted" == "true" && "$exit_code" -ne 0 && ( "$update_state" == "UPDATE_CONFIRMED" || "$update_state" == "ROLLBACK_REQUIRED" ) ]]; then
    classify_rollback_ownership
    case "$rollback_ownership" in
      TARGET_OWNED)
        echo "Existing task-definition switch failed; restoring ${PREVIOUS_TASK_DEFINITION_ARN}." >&2
        if WAIT_FOR_STABLE=true \
          AWS_REGION="$AWS_REGION" \
          CLUSTER_NAME="$CLUSTER_NAME" \
          SERVICE_NAME="$SERVICE_NAME" \
          PREVIOUS_TASK_DEFINITION_ARN="$PREVIOUS_TASK_DEFINITION_ARN" \
          "$REPO_ROOT/scripts/aws/rollback-ecs-service.sh" && verify_existing_service_restored; then
          rollback_result="VERIFIED_SOURCE"
        else
          rollback_result="FAILED_OR_UNVERIFIED"
          echo "Canonical rollback or verification failed." >&2
        fi
        ;;
      PREVIOUS_RESTORED)
        echo "Previous task definition is already restored; no rollback required." >&2
        rollback_result="SOURCE_ALREADY_RESTORED"
        ;;
      FOREIGN)
        echo "CONCURRENT_SERVICE_STATE: refusing to overwrite a foreign ECS task definition." >&2
        rollback_result="FOREIGN_STATE"
        ;;
      *)
        echo "UNKNOWN_ROLLBACK_OWNERSHIP: refusing rollback because current ECS service ownership could not be established." >&2
        rollback_result="UNKNOWN_STATE"
        ;;
    esac
  fi
  if [[ -n "${NORMAL_ACTIVATION_OUTCOME_FILE:-}" ]]; then
    node --input-type=module - "$NORMAL_ACTIVATION_OUTCOME_FILE" "$exit_code" "$update_state" "$rollback_result" <<'NODE'
import fs from "node:fs";
const [file, exitCode, updateState, rollbackResult] = process.argv.slice(2);
fs.writeFileSync(file, `${JSON.stringify({ schemaVersion: 1, exitCode: Number(exitCode), updateState, rollbackResult })}\n`, { mode: 0o600 });
NODE
  fi
  rm -f \
    "$RAW_FILE" \
    "$PAYLOAD_FILE" \
    "$EXISTING_SERVICE_FILE" \
    "$EXISTING_POST_SERVICE_FILE" \
    "$EXISTING_TASKS_LIST_FILE" \
    "$EXISTING_TASKS_RAW_FILE" \
    "$EXISTING_TASKS_FILE" \
    "$EXISTING_CALLER_FILE" \
    "$ROLLBACK_TASK_DEFINITION_FILE" \
    "$ROLLBACK_IMAGE_FILE"
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
  require_version_verification_inputs
  require_existing_activation_authorization

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

  validate_service_load_balancer_compatibility "$EXISTING_SERVICE_FILE" "$RAW_FILE"

CURRENT_EXECUTE_COMMAND_ENABLED="$(node --input-type=module - "$EXISTING_SERVICE_FILE" <<'NODE'
import fs from "node:fs";
const response = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
if (!Array.isArray(response.failures) || response.failures.length !== 0 || response.services?.length !== 1) throw new Error("ECS service response is malformed.");
process.stdout.write(response.services[0].enableExecuteCommand === true ? "true" : "false");
NODE
)"

CURRENT_PROPAGATE_TAGS="$(node --input-type=module - "$EXISTING_SERVICE_FILE" <<'NODE'
import fs from "node:fs";
const response = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
if (!Array.isArray(response.failures) || response.failures.length !== 0 || response.services?.length !== 1) throw new Error("ECS service response is malformed.");
process.stdout.write(response.services[0].propagateTags || "");
NODE
)"

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
const targetTags = new Map((targetResponse.tags || []).map((tag) => [tag?.key, tag?.value]));
if (targetTags.get("MSCQRExecTarget") !== "production-backend") fail("Target task definition lacks the reviewed MSCQRExecTarget marker.");
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

  aws ecs describe-task-definition --region "$AWS_REGION" --task-definition "$PREVIOUS_TASK_DEFINITION_ARN" >"$ROLLBACK_TASK_DEFINITION_FILE"
  ROLLBACK_IMAGE_DIGEST="$(node --input-type=module - "$ROLLBACK_TASK_DEFINITION_FILE" "$PREVIOUS_TASK_DEFINITION_ARN" "$CONTAINER_NAME" <<'NODE'
import fs from "node:fs";
const [file, expectedArn, containerName] = process.argv.slice(2);
const task = JSON.parse(fs.readFileSync(file, "utf8")).taskDefinition;
const selected = (task?.containerDefinitions || []).filter(({ name }) => name === containerName);
const match = selected.length === 1 ? /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@(sha256:[a-f0-9]{64})$/.exec(selected[0].image || "") : null;
if (task?.taskDefinitionArn !== expectedArn || !match) throw new Error("Rollback candidate is not one exact immutable production backend image.");
process.stdout.write(match[1]);
NODE
)"
  if ! aws ecr describe-images --region "$AWS_REGION" --repository-name mscqr-backend --image-ids "imageDigest=$ROLLBACK_IMAGE_DIGEST" >"$ROLLBACK_IMAGE_FILE"; then
    echo "Rollback candidate image viability could not be authenticated; refusing deployment." >&2
    exit 1
  fi
  node --input-type=module - "$ROLLBACK_IMAGE_FILE" "$ROLLBACK_IMAGE_DIGEST" <<'NODE'
import fs from "node:fs";
const [file, digest] = process.argv.slice(2);
const details = JSON.parse(fs.readFileSync(file, "utf8")).imageDetails;
if (!Array.isArray(details) || details.length !== 1 || details[0]?.imageDigest !== digest) throw new Error("Rollback candidate image readback does not match the exact immutable digest.");
NODE

  if [[ "$PREVIOUS_TASK_DEFINITION_ARN" != "$EXISTING_TASK_DEFINITION_ARN" || ( "$ENABLE_EXECUTE_COMMAND" == "true" && "$CURRENT_EXECUTE_COMMAND_ENABLED" != "true" ) || ( "$PROPAGATE_TAGS" == "TASK_DEFINITION" && "$CURRENT_PROPAGATE_TAGS" != "TASK_DEFINITION" ) ]]; then
    update_attempted=true
    update_state="UPDATE_ATTEMPTED"
    update_args=(aws ecs update-service \
      --region "$AWS_REGION" \
      --cluster "$CLUSTER_NAME" \
      --service "$SERVICE_NAME" \
      --task-definition "$EXISTING_TASK_DEFINITION_ARN")
    if [[ "$ENABLE_EXECUTE_COMMAND" == "true" ]]; then update_args+=(--enable-execute-command); fi
    if [[ "${PROPAGATE_TAGS:-}" == "TASK_DEFINITION" ]]; then update_args+=(--propagate-tags "$PROPAGATE_TAGS"); fi
    if "${update_args[@]}" >/dev/null; then
      update_state="UPDATE_CONFIRMED"
      existing_switch_started=true
    else
      settle_update_outcome
      case "$settlement_result" in
        TARGET)
          update_state="ROLLBACK_REQUIRED"
          existing_switch_started=true
          echo "AMBIGUOUS_UPDATE_OUTCOME: UpdateService failed after the target became active; restoring the exact previous task definition." >&2
          exit 1
          ;;
        FOREIGN)
          update_state="UPDATE_OUTCOME_AMBIGUOUS"
          echo "AMBIGUOUS_UPDATE_OUTCOME: service task definition or deployment is neither the expected previous nor target ARN: concurrent state requires operator intervention." >&2
          exit 1
          ;;
        UNKNOWN)
          update_state="UPDATE_OUTCOME_AMBIGUOUS"
          echo "UNKNOWN_SERVICE_STATE: UpdateService failed and the bounded settlement window could not establish a safe service state." >&2
          exit 1
          ;;
        *)
          update_state="UPDATE_OUTCOME_AMBIGUOUS"
          echo "AMBIGUOUS_UPDATE_OUTCOME: UpdateService returned nonzero after being attempted; bounded previous-state observations cannot prove rejection, so operator intervention is required." >&2
          exit 1
          ;;
      esac
    fi
  else
    echo "Target task definition and requested service settings are already active on ${SERVICE_NAME}; no service update required."
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

  node --input-type=module - "$EXISTING_POST_SERVICE_FILE" "$EXISTING_TASKS_LIST_FILE" "$EXISTING_TASK_DEFINITION_ARN" "$ENABLE_EXECUTE_COMMAND" <<'NODE'
import fs from "node:fs";
const [servicePath, taskListPath, targetArn, enableExecuteCommand] = process.argv.slice(2);
const response = JSON.parse(fs.readFileSync(servicePath, "utf8"));
const fail = (message) => { throw new Error(message); };
if (!Array.isArray(response.failures) || response.failures.length !== 0) fail("Post-switch ECS service description returned failures.");
if (response.services?.length !== 1) fail("Post-switch ECS service description did not return exactly one service.");
const service = response.services[0];
if (service.status !== "ACTIVE" || service.taskDefinition !== targetArn) fail("Post-switch service is not bound to the exact target task definition.");
if (enableExecuteCommand === "true" && service.enableExecuteCommand !== true) fail("Post-switch service does not have ECS Exec enabled.");
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
    --include TAGS \
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
  if (!Array.isArray(task.tags) || !task.tags.some((tag) => tag?.key === "MSCQRExecTarget" && tag?.value === "production-backend")) fail("A replacement task lacks the reviewed propagated MSCQRExecTarget marker.");
}
NODE

  if [[ -n "${METADATA_FILE:-}" ]]; then
    node --input-type=module - "$METADATA_FILE" "$CLUSTER_NAME" "$SERVICE_NAME" "$CONTAINER_NAME" "$PREVIOUS_TASK_DEFINITION_ARN" "$EXISTING_TASK_DEFINITION_ARN" "$EXPECTED_IMAGE_DIGEST" <<'NODE'
import fs from "node:fs";
const [outPath, clusterName, serviceName, containerName, previousTaskDefinitionArn, targetTaskDefinitionArn, expectedImageDigest] = process.argv.slice(2);
fs.writeFileSync(outPath, JSON.stringify({ mode: "existing-task-definition", clusterName, serviceName, containerName, previousTaskDefinitionArn, targetTaskDefinitionArn, expectedImageDigest }, null, 2));
NODE
  fi

  verify_deployed_version_if_requested

  update_state="VERIFIED"
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

aws ecs describe-services \
  --region "$AWS_REGION" \
  --cluster "$CLUSTER_NAME" \
  --services "$SERVICE_NAME" \
  >"$EXISTING_SERVICE_FILE"
validate_service_load_balancer_compatibility "$EXISTING_SERVICE_FILE" "$PAYLOAD_FILE"

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

update_args=(aws ecs update-service \
  --region "$AWS_REGION" \
  --cluster "$CLUSTER_NAME" \
  --service "$SERVICE_NAME" \
  --task-definition "$NEW_TASK_DEFINITION_ARN")
if [[ "$ENABLE_EXECUTE_COMMAND" == "true" ]]; then update_args+=(--enable-execute-command); fi
if [[ -n "${PROPAGATE_TAGS:-}" ]]; then update_args+=(--propagate-tags "$PROPAGATE_TAGS"); fi
"${update_args[@]}" >/dev/null

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

if [[ "$ENABLE_EXECUTE_COMMAND" == "true" ]]; then
  aws ecs describe-services \
    --region "$AWS_REGION" \
    --cluster "$CLUSTER_NAME" \
    --services "$SERVICE_NAME" \
    >"$EXISTING_POST_SERVICE_FILE"
  node --input-type=module - "$EXISTING_POST_SERVICE_FILE" <<'NODE'
import fs from "node:fs";
const response = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
if (!Array.isArray(response.failures) || response.failures.length !== 0 || response.services?.length !== 1 || response.services[0].enableExecuteCommand !== true) {
  throw new Error("Post-switch service does not have ECS Exec enabled.");
}
NODE
fi
if [[ -n "${PROPAGATE_TAGS:-}" ]]; then
  aws ecs describe-services \
    --region "$AWS_REGION" \
    --cluster "$CLUSTER_NAME" \
    --services "$SERVICE_NAME" \
    >"$EXISTING_POST_SERVICE_FILE"
  node --input-type=module - "$EXISTING_POST_SERVICE_FILE" <<'NODE'
import fs from "node:fs";
const response = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
if (response.services?.[0]?.propagateTags !== "TASK_DEFINITION") throw new Error("Post-switch service does not propagate task-definition tags.");
NODE
fi

echo "Deployed ${SERVICE_NAME} on ${CLUSTER_NAME}"
echo "  Task definition: ${NEW_TASK_DEFINITION_ARN}"
echo "  Container: ${CONTAINER_NAME}"
echo "  Image: ${IMAGE_URI}"

verify_deployed_version_if_requested
