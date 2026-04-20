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
- Added a manual GitHub Actions workflow as the canonical production path:
  - `.github/workflows/publish-ecs-images.yml`
- Updated CI so backend container buildability is validated explicitly for `linux/amd64` with `docker buildx`
- Updated deployment docs to explain:
  - local Apple Silicon Docker behavior
  - ECS/Fargate `X86_64` requirement
  - multi-arch manifest list vs single-arch image

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

Current standard:

- ECS/Fargate runtime stays on `LINUX/X86_64`
- production image tags are immutable Git SHAs
- production publishes use repo-owned buildx automation

## Important Separation Of Concerns

Do not regress the object-storage task-role work already on this branch.

That work is separate from the image-architecture fix and is documented in:

- [docs/aws/object-storage-task-role.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/aws/object-storage-task-role.md:1)
- [docs/aws/chatgpt-handoff-object-storage-task-role.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/aws/chatgpt-handoff-object-storage-task-role.md:1)

## Why This Prevents The Failure

The new standard path prevents the original failure in three ways:

1. Production publishing is explicit and no longer depends on whatever architecture a local laptop happens to use.
2. The default publish output is a multi-arch manifest list that includes `linux/amd64`.
3. The publish flow fails fast if manifest verification does not show the required platform before an operator updates ECS.
