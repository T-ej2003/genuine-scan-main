#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/aws/publish-ecs-images.sh <backend|frontend|worker|rls-executor|rls-canary|production-green-stage-b|both|all>

Build and push the production backend/frontend/worker/runtime-boundary images to ECR with
docker buildx. The default output is an ECS/Fargate-ready linux/amd64 manifest
tagged with the immutable current git SHA.

Environment:
  AWS_REGION         Required AWS region for ECR.
  AWS_ACCOUNT_ID     Optional. Auto-detected via STS when omitted.
  ECR_REGISTRY       Optional. Overrides the computed ECR registry hostname.
  IMAGE_TAG          Optional. Defaults to git rev-parse HEAD.
  SOURCE_RELEASE_SHA Optional source revision for image labels. Defaults to IMAGE_TAG.
  PLATFORMS          Optional. Defaults to linux/amd64.
  BACKEND_ECR_REPO   Optional. Defaults to mscqr-backend.
  FRONTEND_ECR_REPO  Optional. Defaults to mscqr-web.
  WORKER_ECR_REPO    Optional. Defaults to mscqr-worker.
  BACKEND_DOCKERFILE Optional. Defaults to backend/Dockerfile.
  FRONTEND_DOCKERFILE Optional. Defaults to Dockerfile.ecs-frontend.
  WORKER_DOCKERFILE  Optional. Defaults to backend/Dockerfile.
  BACKEND_BUILD_CONTEXT Optional. Defaults to .
  FRONTEND_BUILD_CONTEXT Optional. Defaults to .
  WORKER_BUILD_CONTEXT Optional. Defaults to .
  BUILDER_NAME       Optional. Defaults to mscqr-multiarch.
  OUTPUT_FILE        Optional JSON Lines output file with published image refs.

Examples:
  AWS_REGION=eu-west-2 ./scripts/aws/publish-ecs-images.sh backend
  AWS_REGION=eu-west-2 ./scripts/aws/publish-ecs-images.sh all
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

SERVICE_SCOPE="${1:-}"
if [[ -z "$SERVICE_SCOPE" ]]; then
  usage >&2
  exit 1
fi

case "$SERVICE_SCOPE" in
  backend|frontend|worker|rls-executor|rls-canary|production-green-stage-b|both|all) ;;
  *)
    echo "Expected backend, frontend, worker, rls-executor, rls-canary, production-green-stage-b, both, or all. Got: $SERVICE_SCOPE" >&2
    exit 1
    ;;
esac

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

require_cmd aws
require_cmd docker
require_cmd git

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
if [[ -z "$AWS_REGION" ]]; then
  echo "Set AWS_REGION (or AWS_DEFAULT_REGION) before publishing." >&2
  exit 1
fi

IMAGE_TAG="${IMAGE_TAG:-$(git rev-parse HEAD)}"
SOURCE_RELEASE_SHA="${SOURCE_RELEASE_SHA:-$IMAGE_TAG}"
PLATFORMS="${PLATFORMS:-linux/amd64}"
BACKEND_ECR_REPO="${BACKEND_ECR_REPO:-mscqr-backend}"
FRONTEND_ECR_REPO="${FRONTEND_ECR_REPO:-mscqr-web}"
WORKER_ECR_REPO="${WORKER_ECR_REPO:-mscqr-worker}"
BUILDER_NAME="${BUILDER_NAME:-mscqr-multiarch}"
BACKEND_DOCKERFILE="${BACKEND_DOCKERFILE:-backend/Dockerfile}"
FRONTEND_DOCKERFILE="${FRONTEND_DOCKERFILE:-Dockerfile.ecs-frontend}"
WORKER_DOCKERFILE="${WORKER_DOCKERFILE:-backend/Dockerfile}"
BACKEND_BUILD_CONTEXT="${BACKEND_BUILD_CONTEXT:-.}"
FRONTEND_BUILD_CONTEXT="${FRONTEND_BUILD_CONTEXT:-.}"
WORKER_BUILD_CONTEXT="${WORKER_BUILD_CONTEXT:-.}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERIFY_SCRIPT="$REPO_ROOT/scripts/aws/verify-image-manifest.sh"
STAGE_B_BINDING_SCRIPT="$REPO_ROOT/scripts/aws/stage-b-image-bindings.mjs"

if [[ "$SERVICE_SCOPE" == "production-green-stage-b" ]]; then
  if ! [[ "$IMAGE_TAG" =~ ^[a-f0-9]{40}$ ]] || [[ "$IMAGE_TAG" != "$(git rev-parse HEAD)" ]] || ! [[ "$SOURCE_RELEASE_SHA" =~ ^[a-f0-9]{40}$ ]] || [[ "$SOURCE_RELEASE_SHA" != "$IMAGE_TAG" ]]; then
    echo "Stage B SOURCE_RELEASE_SHA must equal IMAGE_TAG and the checked-out release SHA." >&2
    exit 1
  fi
fi

if [[ -z "${ECR_REGISTRY:-}" ]]; then
  AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
  ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
fi

declare -a SERVICES=()
declare -a REPOSITORIES=()
case "$SERVICE_SCOPE" in
  backend)
    SERVICES=("backend")
    REPOSITORIES=("$BACKEND_ECR_REPO")
    ;;
  frontend)
    SERVICES=("frontend")
    REPOSITORIES=("$FRONTEND_ECR_REPO")
    ;;
  worker)
    SERVICES=("worker")
    REPOSITORIES=("$WORKER_ECR_REPO")
    ;;
  rls-executor)
    SERVICES=("rls-executor")
    REPOSITORIES=("$BACKEND_ECR_REPO")
    ;;
  rls-canary)
    SERVICES=("rls-canary")
    REPOSITORIES=("$BACKEND_ECR_REPO")
    ;;
  production-green-stage-b)
    SERVICES=("backend" "worker" "rls-executor" "rls-canary")
    REPOSITORIES=("$BACKEND_ECR_REPO" "$WORKER_ECR_REPO")
    ;;
  both)
    SERVICES=("backend" "frontend")
    REPOSITORIES=("$BACKEND_ECR_REPO" "$FRONTEND_ECR_REPO")
    ;;
  all)
    SERVICES=("backend" "frontend" "worker" "rls-executor")
    REPOSITORIES=("$BACKEND_ECR_REPO" "$FRONTEND_ECR_REPO" "$WORKER_ECR_REPO")
    ;;
esac

echo "Checking ECR repositories in ${AWS_REGION}: ${REPOSITORIES[*]}"
aws ecr describe-repositories --region "$AWS_REGION" --repository-names "${REPOSITORIES[@]}" >/dev/null

echo "Logging in to ${ECR_REGISTRY}"
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ECR_REGISTRY"

if docker buildx inspect "$BUILDER_NAME" >/dev/null 2>&1; then
  docker buildx use "$BUILDER_NAME" >/dev/null
else
  docker buildx create --name "$BUILDER_NAME" --use >/dev/null
fi
docker buildx inspect --builder "$BUILDER_NAME" --bootstrap >/dev/null

REMOTE_URL="$(git remote get-url origin 2>/dev/null || true)"

if [[ "$SERVICE_SCOPE" == *"rls"* || "$SERVICE_SCOPE" == "production-green-stage-b" ]]; then
  if ! [[ "${SOURCE_CONTRACT_SHA256:-}" =~ ^[a-f0-9]{64}$ ]] || ! [[ "${MIGRATION_SET_DIGEST:-}" =~ ^[a-f0-9]{64}$ ]]; then
    echo "SOURCE_CONTRACT_SHA256 and MIGRATION_SET_DIGEST must be reviewed SHA256 values for Stage B images." >&2
    exit 1
  fi
fi
if [[ "$SERVICE_SCOPE" == "production-green-stage-b" ]]; then
  npm run rls:full-verify >/dev/null
  actual_source_contract="$(node -p 'require("./documents/security/rls-program/generated/checksums.json").sourceContractSha256')"
  actual_migration_digest="$(node -p 'require("./documents/security/rls-program/generated/checksums.json").migrationSetDigest')"
  if [[ "$SOURCE_CONTRACT_SHA256" != "$actual_source_contract" ]] || [[ "$MIGRATION_SET_DIGEST" != "$actual_migration_digest" ]]; then
    echo "Stage B image labels do not match the verified generated RLS package." >&2
    exit 1
  fi
fi
BUILD_TIMESTAMP="${BUILD_TIMESTAMP:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

echo "Publishing ${SERVICE_SCOPE} image(s)"
echo "  Tag: ${IMAGE_TAG}"
echo "  Platforms: ${PLATFORMS}"

image_uri_for_service() {
  local service="$1"
  case "$service" in
    backend) printf '%s/%s:%s' "$ECR_REGISTRY" "$BACKEND_ECR_REPO" "$IMAGE_TAG" ;;
    frontend) printf '%s/%s:%s' "$ECR_REGISTRY" "$FRONTEND_ECR_REPO" "$IMAGE_TAG" ;;
    worker) printf '%s/%s:%s' "$ECR_REGISTRY" "$WORKER_ECR_REPO" "$IMAGE_TAG" ;;
  rls-executor) printf '%s/%s:%s-rls-executor' "$ECR_REGISTRY" "$BACKEND_ECR_REPO" "$IMAGE_TAG" ;;
  rls-canary) printf '%s/%s:%s-rls-canary' "$ECR_REGISTRY" "$BACKEND_ECR_REPO" "$IMAGE_TAG" ;;
    *) echo "Unsupported service: $service" >&2; return 1 ;;
  esac
}

dockerfile_for_service() {
  local service="$1"
  case "$service" in
    backend) printf '%s' "$BACKEND_DOCKERFILE" ;;
    frontend) printf '%s' "$FRONTEND_DOCKERFILE" ;;
    worker) printf '%s' "$WORKER_DOCKERFILE" ;;
  rls-executor|rls-canary) printf '%s' "$BACKEND_DOCKERFILE" ;;
    *) echo "Unsupported service: $service" >&2; return 1 ;;
  esac
}

context_for_service() {
  local service="$1"
  case "$service" in
    backend) printf '%s' "$BACKEND_BUILD_CONTEXT" ;;
    frontend) printf '%s' "$FRONTEND_BUILD_CONTEXT" ;;
    worker) printf '%s' "$WORKER_BUILD_CONTEXT" ;;
  rls-executor|rls-canary) printf '%s' "$BACKEND_BUILD_CONTEXT" ;;
    *) echo "Unsupported service: $service" >&2; return 1 ;;
  esac
}

target_for_service() {
  case "$1" in
    frontend) printf '' ;;
    rls-executor) printf 'production-rls-executor' ;;
    rls-canary) printf 'production-rls-canary' ;;
    backend|worker) printf 'runtime' ;;
    *) echo "Unsupported service: $1" >&2; return 1 ;;
  esac
}

verify_stage_b_reuse() {
  local service="$1" image_uri="$2" labels
  docker pull --platform "$PLATFORMS" "$image_uri" >/dev/null
  labels="$(docker image inspect "$image_uri" --format '{{json .Config.Labels}}')"
  printf '%s' "$labels" | node "$STAGE_B_BINDING_SCRIPT" "$service" "$IMAGE_TAG" "$SOURCE_CONTRACT_SHA256" "$MIGRATION_SET_DIGEST"
}

declare -a IMAGE_URIS=()

for service in "${SERVICES[@]}"; do
  image_uri="$(image_uri_for_service "$service")"
  dockerfile="$(dockerfile_for_service "$service")"
  build_context="$(context_for_service "$service")"
  target="$(target_for_service "$service")"
  published_tag="${image_uri##*:}"
  IMAGE_URIS+=("$image_uri")
  repository_name="${image_uri#${ECR_REGISTRY}/}"
  repository_name="${repository_name%%:*}"
  existing_digest="$(
    aws ecr describe-images \
      --region "$AWS_REGION" \
      --repository-name "$repository_name" \
      --image-ids imageTag="$published_tag" \
      --query 'imageDetails[0].imageDigest' \
      --output text 2>/dev/null || true
  )"

  if [[ "$existing_digest" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    echo "Reusing immutable ${service} image ${image_uri}@${existing_digest}"
    REQUIRED_PLATFORMS="$PLATFORMS" "$VERIFY_SCRIPT" "$image_uri"
    if [[ "$SERVICE_SCOPE" == "production-green-stage-b" ]]; then
      verify_stage_b_reuse "$service" "$image_uri"
    fi
    if [[ -n "${OUTPUT_FILE:-}" ]]; then
      node --input-type=module - "$OUTPUT_FILE" "$service" "$repository_name" "$image_uri" "$published_tag" "$existing_digest" <<'NODE'
import fs from "node:fs";
const [outputPath, service, repositoryName, imageUri, imageTag, imageDigest] = process.argv.slice(2);
fs.appendFileSync(outputPath, `${JSON.stringify({
  service, repository: repositoryName, image_uri: imageUri, image_tag: imageTag,
  image_digest: imageDigest, image_ref: imageUri.replace(/:[^:@]+$/, `@${imageDigest}`),
})}\n`);
NODE
    fi
    continue
  fi

  echo
  echo "Building ${service}"
  echo "  Dockerfile: ${dockerfile}"
  echo "  Context: ${build_context}"
  echo "  Image: ${image_uri}"

  build_args=(
    --builder "$BUILDER_NAME" \
    --platform "$PLATFORMS" \
    --file "$dockerfile" \
    --build-arg "GIT_SHA=${SOURCE_RELEASE_SHA}" \
    --build-arg "RELEASE_GIT_SHA=${SOURCE_RELEASE_SHA}" \
    --build-arg "SOURCE_CONTRACT_SHA256=${SOURCE_CONTRACT_SHA256:-unbound}" \
    --build-arg "MIGRATION_SET_DIGEST=${MIGRATION_SET_DIGEST:-unbound}" \
    --build-arg "BUILD_TIMESTAMP=${BUILD_TIMESTAMP}" \
    --label "org.opencontainers.image.revision=${SOURCE_RELEASE_SHA}" \
    --label "org.opencontainers.image.source=${REMOTE_URL}" \
    --label "org.opencontainers.image.created=${BUILD_TIMESTAMP}" \
    --label "com.mscqr.rls.source-contract-sha256=${SOURCE_CONTRACT_SHA256:-unbound}" \
    --label "com.mscqr.rls.migration-set-digest=${MIGRATION_SET_DIGEST:-unbound}" \
    --label "org.opencontainers.image.title=mscqr-${service}"
  )
  if [[ -n "$target" ]]; then
    build_args+=(--target "$target")
  fi
  docker buildx build \
    "${build_args[@]}" \
    --push \
    --tag "$image_uri" \
    "$build_context"

  REQUIRED_PLATFORMS="$PLATFORMS" "$VERIFY_SCRIPT" "$image_uri"

  if [[ -n "${OUTPUT_FILE:-}" ]]; then
    image_digest="$(
      aws ecr describe-images \
        --region "$AWS_REGION" \
        --repository-name "$repository_name" \
        --image-ids imageTag="$published_tag" \
        --query 'imageDetails[0].imageDigest' \
        --output text
    )"
    node --input-type=module - "$OUTPUT_FILE" "$service" "$repository_name" "$image_uri" "$published_tag" "$image_digest" <<'NODE'
import fs from "node:fs";

const [outputPath, service, repositoryName, imageUri, imageTag, imageDigest] = process.argv.slice(2);
const record = {
  service,
  repository: repositoryName,
  image_uri: imageUri,
  image_tag: imageTag,
  image_digest: imageDigest,
  image_ref: imageUri.replace(/:[^:@]+$/, `@${imageDigest}`),
};
fs.appendFileSync(outputPath, `${JSON.stringify(record)}\n`);
NODE
  fi
  echo
done

echo "Published image tag ${IMAGE_TAG} to:"
printf '  - %s\n' "${IMAGE_URIS[@]}"
