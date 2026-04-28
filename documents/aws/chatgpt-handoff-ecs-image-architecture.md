# ChatGPT Handoff: ECS/Fargate Image Architecture And ECR Publishing

## Root Cause

Production ECS/Fargate tasks currently run on `LINUX/X86_64`, but an image was pushed to ECR without a `linux/amd64` manifest descriptor.

The most likely cause was a normal Docker build/push flow executed from Apple Silicon:

- local Docker built a host-native `arm64` image
- that single-arch image was pushed to ECR
- ECS/Fargate could not resolve a matching `linux/amd64` image manifest during deployment

This is a production publishing problem, not an ECS CPU-architecture problem.

## What Changed

- Added repo-owned production publish script:
  - `scripts/aws/publish-ecs-images.sh`
- Added repo-owned manifest verification script:
  - `scripts/aws/verify-image-manifest.sh`
- Added repo-owned ECR control enforcement script:
  - `scripts/aws/apply-ecr-repository-controls.sh`
- Added repo-owned ECS rollout helper:
  - `scripts/aws/deploy-ecs-service.sh`
- Added repo-owned ECS rollback helper:
  - `scripts/aws/rollback-ecs-service.sh`
- Added repo-owned runtime SHA smoke-check helper:
  - `scripts/aws/verify-version-endpoint.sh`
- Added repo-owned readiness smoke-check helper:
  - `scripts/aws/verify-ready-endpoint.sh`
- Added repo-owned signed release verification helper:
  - `scripts/aws/verify-release-artifacts.sh`
- Added a manual GitHub Actions workflow as the canonical production path:
  - `.github/workflows/publish-ecs-images.yml`
- Added a manual audited deploy workflow:
  - `.github/workflows/deploy-ecs-release.yml`
- Added a Terraform baseline for ECR and ECS drift control:
  - `infra/aws/terraform/`
- Updated CI so backend container buildability is validated explicitly for `linux/amd64` with `docker buildx`
- Updated deployment docs to explain:
  - local Apple Silicon Docker behavior
  - ECS/Fargate `X86_64` requirement
  - multi-arch manifest list vs single-arch image
- Updated `/version` so post-deploy smoke checks can confirm the exact `GIT_SHA` serving in production.
- ECR repositories now enforce immutable tags and lifecycle cleanup for stale release images.

Backend and worker still use the same runtime image content from `backend/Dockerfile`, but stay in separate ECR repositories for operational clarity.

## Exact Build And Push Commands

Set environment first:

```bash
export AWS_REGION=eu-west-2
export AWS_ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
export IMAGE_TAG="$(git rev-parse HEAD)"
export ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
export BACKEND_ECR_REPO=mscqr-backend
export WORKER_ECR_REPO=mscqr-worker
```

Publish backend only:

```bash
./scripts/aws/publish-ecs-images.sh backend
```

Publish worker only:

```bash
./scripts/aws/publish-ecs-images.sh worker
```

Publish both with the same immutable Git SHA tag:

```bash
./scripts/aws/apply-ecr-repository-controls.sh both
./scripts/aws/publish-ecs-images.sh both
```

## Exact Manifest Verification Commands

```bash
REQUIRED_PLATFORMS=linux/amd64,linux/arm64 \
  ./scripts/aws/verify-image-manifest.sh "${ECR_REGISTRY}/${BACKEND_ECR_REPO}:${IMAGE_TAG}"

REQUIRED_PLATFORMS=linux/amd64,linux/arm64 \
  ./scripts/aws/verify-image-manifest.sh "${ECR_REGISTRY}/${WORKER_ECR_REPO}:${IMAGE_TAG}"
```

If `linux/amd64` is missing, stop and do not update ECS.

## Signed Release Verification

```bash
export COSIGN_CERT_IDENTITY_REGEXP='^https://github.com/T-ej2003/genuine-scan-main/.github/workflows/(publish-ecs-images|deploy-ecs-release).yml@.*$'

REQUIRED_PLATFORMS=linux/amd64,linux/arm64 \
  ./scripts/aws/verify-release-artifacts.sh \
  "${ECR_REGISTRY}/${BACKEND_ECR_REPO}@sha256:<digest>"
```

That now verifies:

- required manifest platforms
- cosign signature
- SBOM attestation
- release-provenance attestation

## Exact ECS Deployment Follow-Up Steps

1. Verify the backend image manifest includes `linux/amd64`.
2. Verify the worker image manifest includes `linux/amd64`.
3. Update the backend ECS task definition to the SHA-tagged backend image URI.
4. Register the backend task-definition revision.
5. Deploy the backend ECS service.
6. Update the worker ECS task definition to the SHA-tagged worker image URI.
7. Register the worker task-definition revision.
8. Deploy the worker ECS service.
9. Confirm service health and startup logs.
10. Confirm the backend `/version` endpoint reports the expected full `GIT_SHA`.

Direct helper commands:

```bash
export IMAGE_URI="${ECR_REGISTRY}/${BACKEND_ECR_REPO}@sha256:<digest>"
export CLUSTER_NAME=mscqr-prod
export SERVICE_NAME=mscqr-backend
export TASK_DEFINITION=mscqr-backend
export CONTAINER_NAME=backend
export VERSION_URL=https://api.example.com/version
export EXPECTED_GIT_SHA="$IMAGE_TAG"

./scripts/aws/deploy-ecs-service.sh
./scripts/aws/verify-version-endpoint.sh "$VERSION_URL" "$EXPECTED_GIT_SHA"
```

Current standard:

- ECS/Fargate runtime stays on `LINUX/X86_64`
- production image tags are immutable Git SHAs
- production publishes use repo-owned buildx automation
- deployment approvals are staged across protected environments
- backend canary must pass `/version` and `/health/ready` checks before worker rollout

## Important Separation Of Concerns

Do not regress the object-storage task-role work already on this branch.

That work is separate from the image-architecture fix and is documented in:

- [documents/aws/object-storage-task-role.md](/Users/abhiramteja/Downloads/genuine-scan-main/documents/aws/object-storage-task-role.md:1)
- [documents/aws/chatgpt-handoff-object-storage-task-role.md](/Users/abhiramteja/Downloads/genuine-scan-main/documents/aws/chatgpt-handoff-object-storage-task-role.md:1)

## Why This Prevents The Failure

The new standard path prevents the original failure in three ways:

1. Production publishing is explicit and no longer depends on whatever architecture a local laptop happens to use.
2. The default publish output is a multi-arch manifest list that includes `linux/amd64`.
3. ECR repos are hardened with immutable tags and lifecycle cleanup, so stale images do not accumulate and mutable-tag drift is blocked.
4. The release flow now signs images and attaches SBOM plus provenance attestations, then verifies them before deployment.
5. The deploy flow fails fast if post-rollout `/version` or `/health/ready` does not match the expected healthy release, and rolls the backend back before worker promotion.
