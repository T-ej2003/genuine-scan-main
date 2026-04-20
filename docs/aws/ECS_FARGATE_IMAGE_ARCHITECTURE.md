# ECS/Fargate Image Architecture And ECR Publishing

This runbook defines the production-standard path for publishing MSCQR backend and worker images to Amazon ECR for ECS/Fargate.

## Why This Exists

Recent deployment failures happened because a backend image was pushed to ECR without a `linux/amd64` manifest descriptor. That usually happens when a normal `docker build` is run on Apple Silicon and the resulting `arm64` image is pushed directly.

Current production ECS/Fargate tasks run on:

- `operatingSystemFamily=LINUX`
- `cpuArchitecture=X86_64`

That means the production image must include `linux/amd64` before you update any ECS task definition.

## Local Docker vs Production ECS

These are intentionally different workflows:

- Local Docker Compose:
  - developer-native
  - builds for the host architecture unless told otherwise
  - perfectly fine on Apple Silicon for local work
- Production ECR publishing:
  - must be explicit
  - must use `docker buildx`
  - must verify the manifest before ECS deployment

Do not treat a local `docker compose build` as a production publish step.

## Standard Production Strategy

MSCQR uses one runtime Dockerfile for both backend and worker:

- `backend/Dockerfile`

Backend and worker still publish to separate ECR repositories by default:

- `mscqr-backend`
- `mscqr-worker`

The standard production output is a multi-arch manifest list that includes:

- `linux/amd64`
- `linux/arm64`

Why multi-arch is the default:

- it fixes the current ECS `linux/amd64` failure mode
- it keeps Apple Silicon operators from accidentally publishing arm64-only images
- it preserves future flexibility if you later add ARM-based ECS capacity for cost/performance reasons

## Repo-Owned Production Publish Commands

Use immutable Git SHA tags only.

Set your environment first:

```bash
export AWS_REGION=eu-west-2
export AWS_ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
export IMAGE_TAG="$(git rev-parse HEAD)"
export ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
export BACKEND_ECR_REPO=mscqr-backend
export WORKER_ECR_REPO=mscqr-worker
```

### Build and push backend image

```bash
./scripts/aws/publish-ecs-images.sh backend
```

### Build and push worker image

```bash
./scripts/aws/publish-ecs-images.sh worker
```

### Recommended combined publish command

This publishes the same runtime image content to both ECR repositories with one immutable Git SHA tag:

```bash
./scripts/aws/publish-ecs-images.sh both
```

## Exact Manifest Verification Commands

Run these before any ECS task-definition update:

```bash
REQUIRED_PLATFORMS=linux/amd64,linux/arm64 \
  ./scripts/aws/verify-image-manifest.sh "${ECR_REGISTRY}/${BACKEND_ECR_REPO}:${IMAGE_TAG}"

REQUIRED_PLATFORMS=linux/amd64,linux/arm64 \
  ./scripts/aws/verify-image-manifest.sh "${ECR_REGISTRY}/${WORKER_ECR_REPO}:${IMAGE_TAG}"
```

Expected outcome:

- the command prints the discovered platforms
- `linux/amd64` is present
- `linux/arm64` is present for the standard multi-arch publish path

If `linux/amd64` is missing, stop. Do not update the ECS task definition.

## GitHub Actions Canonical Path

The canonical production path is the manual GitHub Actions workflow:

- `.github/workflows/publish-ecs-images.yml`

Workflow behavior:

- uses `docker buildx`
- uses immutable Git SHA tags
- prefers AWS OIDC role auth through repository variable `AWS_ROLE_TO_ASSUME`
- can fall back to `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` secrets if OIDC is not yet wired
- verifies manifest platforms after publish
- prints exact image URIs and manifest results in the workflow summary

Use the workflow for routine production publishing. Use the shell scripts when you need the same process locally or from an ops runner.

## Exact ECS Follow-Up Steps

After the publish and manifest verification succeed:

1. Open the backend ECS task definition.
2. Update the backend container image to:
   - `${ECR_REGISTRY}/${BACKEND_ECR_REPO}:${IMAGE_TAG}`
3. Register the new task-definition revision.
4. Deploy that revision to the backend ECS service.
5. Open the worker ECS task definition.
6. Update the worker container image to:
   - `${ECR_REGISTRY}/${WORKER_ECR_REPO}:${IMAGE_TAG}`
7. Register the new worker task-definition revision.
8. Deploy that revision to the worker ECS service.
9. Verify service startup and readiness after rollout.
10. Keep ECS task CPU architecture on `X86_64` unless you intentionally design and validate an infrastructure migration.

## What Not To Do

- do not publish production images with a plain `docker build` from an Apple Silicon laptop
- do not assume a tag is safe just because it exists in ECR
- do not change ECS task CPU architecture as a workaround for a bad image manifest
- do not mix this image-architecture fix with the object-storage task-role contract

For the ECS object-storage credential contract, see:

- [docs/aws/object-storage-task-role.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/aws/object-storage-task-role.md:1)

For a future ChatGPT/operator handoff version of this runbook, see:

- [docs/aws/chatgpt-handoff-ecs-image-architecture.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/aws/chatgpt-handoff-ecs-image-architecture.md:1)
