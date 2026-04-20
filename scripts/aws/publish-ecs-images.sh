#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/aws/publish-ecs-images.sh <backend|worker|both>

Build and push the production backend/worker runtime image to ECR with docker
buildx. The default output is a multi-arch manifest list for linux/amd64 and
linux/arm64, tagged with the immutable current git SHA.

Environment:
  AWS_REGION         Required AWS region for ECR.
  AWS_ACCOUNT_ID     Optional. Auto-detected via STS when omitted.
  ECR_REGISTRY       Optional. Overrides the computed ECR registry hostname.
  IMAGE_TAG          Optional. Defaults to git rev-parse HEAD.
  PLATFORMS          Optional. Defaults to linux/amd64,linux/arm64.
  BACKEND_ECR_REPO   Optional. Defaults to mscqr-backend.
  WORKER_ECR_REPO    Optional. Defaults to mscqr-worker.
  BUILDER_NAME       Optional. Defaults to mscqr-multiarch.

Examples:
  AWS_REGION=eu-west-2 ./scripts/aws/publish-ecs-images.sh backend
  AWS_REGION=eu-west-2 ./scripts/aws/publish-ecs-images.sh both
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
  backend|worker|both) ;;
  *)
    echo "Expected backend, worker, or both. Got: $SERVICE_SCOPE" >&2
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
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
BACKEND_ECR_REPO="${BACKEND_ECR_REPO:-mscqr-backend}"
WORKER_ECR_REPO="${WORKER_ECR_REPO:-mscqr-worker}"
BUILDER_NAME="${BUILDER_NAME:-mscqr-multiarch}"
DOCKERFILE="${DOCKERFILE:-backend/Dockerfile}"
BUILD_CONTEXT="${BUILD_CONTEXT:-.}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERIFY_SCRIPT="$REPO_ROOT/scripts/aws/verify-image-manifest.sh"

if [[ -z "${ECR_REGISTRY:-}" ]]; then
  AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
  ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
fi

declare -a REPOSITORIES=()
case "$SERVICE_SCOPE" in
  backend)
    REPOSITORIES=("$BACKEND_ECR_REPO")
    ;;
  worker)
    REPOSITORIES=("$WORKER_ECR_REPO")
    ;;
  both)
    REPOSITORIES=("$BACKEND_ECR_REPO" "$WORKER_ECR_REPO")
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

declare -a TAG_ARGS=()
declare -a IMAGE_URIS=()
for repo_name in "${REPOSITORIES[@]}"; do
  image_uri="${ECR_REGISTRY}/${repo_name}:${IMAGE_TAG}"
  TAG_ARGS+=(--tag "$image_uri")
  IMAGE_URIS+=("$image_uri")
done

REMOTE_URL="$(git remote get-url origin 2>/dev/null || true)"

echo "Publishing ${SERVICE_SCOPE} image(s)"
echo "  Tag: ${IMAGE_TAG}"
echo "  Platforms: ${PLATFORMS}"

docker buildx build \
  --builder "$BUILDER_NAME" \
  --platform "$PLATFORMS" \
  --file "$DOCKERFILE" \
  --build-arg "GIT_SHA=${IMAGE_TAG}" \
  --label "org.opencontainers.image.revision=${IMAGE_TAG}" \
  --label "org.opencontainers.image.source=${REMOTE_URL}" \
  --push \
  "${TAG_ARGS[@]}" \
  "$BUILD_CONTEXT"

echo
for image_uri in "${IMAGE_URIS[@]}"; do
  REQUIRED_PLATFORMS="$PLATFORMS" "$VERIFY_SCRIPT" "$image_uri"
  echo
done

echo "Published image tag ${IMAGE_TAG} to:"
printf '  - %s\n' "${IMAGE_URIS[@]}"
