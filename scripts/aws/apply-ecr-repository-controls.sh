#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/aws/apply-ecr-repository-controls.sh <backend|frontend|worker|both|all>

Verify production ECR retention controls before publishing:
- immutable tags and scan on push
- no automatic lifecycle expiration
- repository-level deletion guard

Environment:
  MSCQR_AWS_CREDENTIAL_SOURCE Required: github-oidc-release-deployer, github-access-keys, or named-profile.
  MSCQR_AWS_NAMED_PROFILE Required only for named-profile execution.
  AWS_REGION          Required AWS region for ECR.
  BACKEND_ECR_REPO    Optional. Default: mscqr-backend
  FRONTEND_ECR_REPO   Optional. Default: mscqr-web
  WORKER_ECR_REPO     Optional. Default: mscqr-worker

Examples:
  MSCQR_AWS_CREDENTIAL_SOURCE=named-profile MSCQR_AWS_NAMED_PROFILE=mscqr-production-release-deployer AWS_REGION=eu-west-2 ./scripts/aws/apply-ecr-repository-controls.sh all
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
  backend|frontend|worker|both|all) ;;
  *)
    echo "Expected backend, frontend, worker, both, or all. Got: $SERVICE_SCOPE" >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=production-credential-source.sh
source "$SCRIPT_DIR/production-credential-source.sh"
configure_production_aws_credential_source

if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI is required." >&2
  exit 1
fi

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
if [[ -z "$AWS_REGION" ]]; then
  echo "Set AWS_REGION (or AWS_DEFAULT_REGION) before checking ECR controls." >&2
  exit 1
fi

BACKEND_ECR_REPO="${BACKEND_ECR_REPO:-mscqr-backend}"
FRONTEND_ECR_REPO="${FRONTEND_ECR_REPO:-mscqr-web}"
WORKER_ECR_REPO="${WORKER_ECR_REPO:-mscqr-worker}"

declare -a REPOSITORIES=()
case "$SERVICE_SCOPE" in
  backend) REPOSITORIES=("$BACKEND_ECR_REPO") ;;
  frontend) REPOSITORIES=("$FRONTEND_ECR_REPO") ;;
  worker) REPOSITORIES=("$WORKER_ECR_REPO") ;;
  both) REPOSITORIES=("$BACKEND_ECR_REPO" "$FRONTEND_ECR_REPO") ;;
  all) REPOSITORIES=("$BACKEND_ECR_REPO" "$FRONTEND_ECR_REPO" "$WORKER_ECR_REPO") ;;
esac

for repository_name in "${REPOSITORIES[@]}"; do
  node "$SCRIPT_DIR/verify-production-ecr-repository-protection.mjs" "$repository_name" "$AWS_REGION"
done

echo "Verified ECR retention controls in ${AWS_REGION}:"
printf '  - %s\n' "${REPOSITORIES[@]}"
echo "  - immutable tags, scan on push, no lifecycle expiration, deletion guard"
