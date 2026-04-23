#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/aws/rollback-ecs-service.sh

Rollback an ECS service to a previous task definition revision.

Required environment:
  AWS_REGION                     AWS region for ECS.
  CLUSTER_NAME                   ECS cluster name.
  SERVICE_NAME                   ECS service name.
  PREVIOUS_TASK_DEFINITION_ARN   Task definition ARN to restore.

Optional environment:
  WAIT_FOR_STABLE   Default: true
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI is required." >&2
  exit 1
fi

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
WAIT_FOR_STABLE="${WAIT_FOR_STABLE:-true}"

for required in AWS_REGION CLUSTER_NAME SERVICE_NAME PREVIOUS_TASK_DEFINITION_ARN; do
  if [[ -z "${!required:-}" ]]; then
    echo "Missing required environment variable: ${required}" >&2
    exit 1
  fi
done

aws ecs update-service \
  --region "$AWS_REGION" \
  --cluster "$CLUSTER_NAME" \
  --service "$SERVICE_NAME" \
  --task-definition "$PREVIOUS_TASK_DEFINITION_ARN" \
  >/dev/null

if [[ "$WAIT_FOR_STABLE" == "true" ]]; then
  aws ecs wait services-stable \
    --region "$AWS_REGION" \
    --cluster "$CLUSTER_NAME" \
    --services "$SERVICE_NAME"
fi

echo "Rolled back ${SERVICE_NAME} on ${CLUSTER_NAME} to ${PREVIOUS_TASK_DEFINITION_ARN}"
