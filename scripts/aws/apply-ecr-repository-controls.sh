#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/aws/apply-ecr-repository-controls.sh <backend|worker|both>

Apply production ECR hardening controls for the MSCQR ECS images:
- immutable tags
- lifecycle policy for stale images

Environment:
  AWS_REGION          Required AWS region for ECR.
  BACKEND_ECR_REPO    Optional. Default: mscqr-backend
  WORKER_ECR_REPO     Optional. Default: mscqr-worker
  KEEP_TAGGED_COUNT   Optional. Default: 120
  UNTAGGED_DAYS       Optional. Default: 7

Examples:
  AWS_REGION=eu-west-2 ./scripts/aws/apply-ecr-repository-controls.sh both
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

if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI is required." >&2
  exit 1
fi

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
if [[ -z "$AWS_REGION" ]]; then
  echo "Set AWS_REGION (or AWS_DEFAULT_REGION) before applying ECR controls." >&2
  exit 1
fi

BACKEND_ECR_REPO="${BACKEND_ECR_REPO:-mscqr-backend}"
WORKER_ECR_REPO="${WORKER_ECR_REPO:-mscqr-worker}"
KEEP_TAGGED_COUNT="${KEEP_TAGGED_COUNT:-120}"
UNTAGGED_DAYS="${UNTAGGED_DAYS:-7}"

declare -a REPOSITORIES=()
case "$SERVICE_SCOPE" in
  backend) REPOSITORIES=("$BACKEND_ECR_REPO") ;;
  worker) REPOSITORIES=("$WORKER_ECR_REPO") ;;
  both) REPOSITORIES=("$BACKEND_ECR_REPO" "$WORKER_ECR_REPO") ;;
esac

POLICY_FILE="$(mktemp)"
trap 'rm -f "$POLICY_FILE"' EXIT

node --input-type=module - "$KEEP_TAGGED_COUNT" "$UNTAGGED_DAYS" >"$POLICY_FILE" <<'NODE'
const [keepTaggedCountText, untaggedDaysText] = process.argv.slice(2);
const keepTaggedCount = Number(keepTaggedCountText);
const untaggedDays = Number(untaggedDaysText);

if (!Number.isInteger(keepTaggedCount) || keepTaggedCount < 1) {
  throw new Error("KEEP_TAGGED_COUNT must be a positive integer.");
}
if (!Number.isInteger(untaggedDays) || untaggedDays < 1) {
  throw new Error("UNTAGGED_DAYS must be a positive integer.");
}

const policy = {
  rules: [
    {
      rulePriority: 1,
      description: `Expire untagged images older than ${untaggedDays} days`,
      selection: {
        tagStatus: "untagged",
        countType: "sinceImagePushed",
        countUnit: "days",
        countNumber: untaggedDays,
      },
      action: { type: "expire" },
    },
    {
      rulePriority: 2,
      description: `Keep only the newest ${keepTaggedCount} release manifests overall`,
      selection: {
        tagStatus: "any",
        countType: "imageCountMoreThan",
        countNumber: keepTaggedCount,
      },
      action: { type: "expire" },
    },
  ],
};

process.stdout.write(JSON.stringify(policy));
NODE

for repository_name in "${REPOSITORIES[@]}"; do
  echo "Applying immutable tag policy to ${repository_name}"
  aws ecr put-image-tag-mutability \
    --region "$AWS_REGION" \
    --repository-name "$repository_name" \
    --image-tag-mutability IMMUTABLE \
    >/dev/null

  echo "Applying lifecycle policy to ${repository_name}"
  aws ecr put-lifecycle-policy \
    --region "$AWS_REGION" \
    --repository-name "$repository_name" \
    --lifecycle-policy-text "file://${POLICY_FILE}" \
    >/dev/null
done

echo "Applied ECR controls in ${AWS_REGION}:"
printf '  - %s\n' "${REPOSITORIES[@]}"
echo "  - imageTagMutability=IMMUTABLE"
echo "  - lifecycle keeps the newest ${KEEP_TAGGED_COUNT} release images and expires untagged images older than ${UNTAGGED_DAYS} days"
