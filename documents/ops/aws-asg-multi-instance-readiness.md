# AWS ASG Multi-Instance Readiness

Last updated: 2026-05-28

ASG_STATUS=CONDITIONALLY_READY

Do not create ASGs. Do not attach instances to ASGs. Do not perform production DNS cutover. Do not mutate RDS data. Do not delete AWS resources. This document is a code, configuration, and runbook audit for preparing MSCQR to run safely behind regional ALBs with two or more EC2 instances.

## Executive Verdict

MSCQR is conditionally ready for a first controlled ASG rollout rehearsal, but it is not yet live-proven.

The app has several good production controls already:

- Production startup refuses to run without Redis coordination.
- Production startup refuses to run without object storage.
- Mumbai and Cape Town have operator-proven regional ElastiCache/Valkey reachable from EC2 with `REDIS_URL=rediss://regional-elasticache:6379/0` and `REDIS_TLS=true`.
- Mumbai and Cape Town have operator-proven regional S3/default credential object storage with `endpoint=null`, `mode=default-credentials`, and empty static object storage credential fields.
- Backend container startup defaults `RUN_DB_MIGRATIONS_ON_START=false`.
- Docker Compose disables background workers in the HTTP backend with `RUN_BACKGROUND_WORKERS=false`.
- Docker Compose now keeps the worker behind the explicit `worker` profile.
- `docker-compose.asg-web.yml` is the ASG web-node mode and contains only `backend` and `frontend`.
- ASG backend container health uses `/health/live` for process liveness so frontend/Nginx can start; bootstrap still gates success on `/api/health/ready`.
- `scripts/dr/bootstrap-asg-web-node.sh` is the committed ASG web-node bootstrap path using AWS SSM Parameter Store.
- `documents/ops/aws-asg-web-ssm-parameter-manifest.json` records required root/backend env parameter names without values.
- ASG launch-template plan/apply now requires explicit `ASG_WEB_INSTANCE_PROFILE_ARN` or `ASG_WEB_INSTANCE_PROFILE_NAME`.
- ASG launch-template plan/apply now emits base64 `UserData` that can boot a plain Ubuntu 22.04 host by installing/checking Git, Docker, Docker Compose, AWS CLI, Node.js 24, and npm 11, including apt attempts plus manual Docker Compose/AWS CLI fallbacks and pinned-major NodeSource setup, cloning/updating the repository, and then running the ASG web bootstrap script from `ASG_REPO_DIR`.
- ASG launch-template plan/apply now supports explicit `ASG_ASSOCIATE_PUBLIC_IP=true|false` networking, with `false` as the default.
- ASG launch-template plan/apply now supports optional `ASG_KEY_NAME`; Mumbai debug retry should use `ASG_KEY_NAME=mscqr-prod-mumbai`.
- ASG launch-template plan/apply now supports `ASG_REPO_URL`, `ASG_REPO_BRANCH`, and `ASG_REPO_DIR`; Mumbai debug retry should use `ASG_REPO_URL=https://github.com/T-ej2003/genuine-scan-main.git`, `ASG_REPO_BRANCH=main`, and `ASG_REPO_DIR=/home/ubuntu/genuine-scan-main`.
- `documents/ops/aws-asg-rolling-deploy-policy.md` and `documents/ops/aws-asg-rolling-deploy-policy.checklist.json` define the rolling deploy contract, rollback criteria, and replacement-instance drill.
- `/healthz` exists for shallow app liveness and `/api/health/ready` reaches backend dependency readiness through Nginx.

The remaining go/no-go is live validation, not a missing repo artifact:

- First regional ASG create/attach must be run as a no-production-DNS rehearsal.
- One replacement-instance drill must prove target replacement, alarms, and rollback behavior with evidence.
- Some upload flows stage files on local disk before object-storage upload. That is acceptable only as short-lived temp/staging, not as persistent state.

## Architecture Evidence

Repository shape:

- Frontend: Vite/React static bundle served by Nginx.
- Backend: Express/Prisma service in `backend/src/index.ts`.
- Worker: `backend/src/worker.ts` using the same backend image with a worker entrypoint.
- Legacy/local orchestration: `docker-compose.yml` with `frontend`, `backend`, profiled `worker`, `redis`, `minio`, and `minio-init`.
- ASG web-node orchestration: `docker-compose.asg-web.yml` with `frontend` and `backend` only.
- Database: Prisma/PostgreSQL through `DATABASE_URL`.
- Object storage: S3-compatible client in `backend/src/services/objectStorageService.ts`.

Runtime defaults that matter for ASG:

- `backend/Dockerfile` sets `RUN_DB_MIGRATIONS_ON_START=false`.
- `backend/docker/start-runtime.sh` runs `npx prisma migrate deploy` only when `RUN_DB_MIGRATIONS_ON_START=true`.
- `docker-compose.yml` sets backend `RUN_BACKGROUND_WORKERS: "false"`.
- `docker-compose.yml` puts the `worker` service behind `profiles: ["worker"]` and sets worker `RUN_BACKGROUND_WORKERS: "true"`.
- `docker-compose.asg-web.yml` has no `worker`, `redis`, `minio`, or `minio-init` service.
- `docker-compose.asg-web.yml` uses backend `/health/live` for container health and keeps `/api/health/ready` as the deeper dependency readiness gate.
- `docker-compose.yml` defaults `REDIS_URL` to `redis://redis:6379/0`.
- `docker-compose.yml` includes local `minio_data` and `redis_data` volumes.

## A. Redis And Sessions

Evidence:

- Redis is configured by `REDIS_URL` or `REDIS_HOST`/`REDIS_PORT` in `backend/src/services/redisService.ts`.
- Production startup in `backend/src/index.ts` refuses to start when Redis is not configured.
- Public rate limits use `rate-limit-redis` when Redis is configured.
- Incident report rate limits, versioned cache invalidation, audit/notification pub-sub, and distributed leases use Redis when configured.
- Auth sessions are JWT/cookie-backed, not Express in-memory sessions. No `express-session` MemoryStore was found in backend source.
- Operator evidence confirms both Mumbai and Cape Town regional EC2 instances are using regional ElastiCache/Valkey via `rediss://regional-elasticache:6379/0`, `REDIS_TLS=true`.
- `/api/health/ready` in both regions reports Redis `configured=true` and `ready=true`.

Residual risk:

- Local Redis per EC2 node would split rate limits, leases, cache invalidation, notifications, and pub-sub if the legacy Compose file is copied directly into ASG web nodes.
- Any in-process fallback is for local/non-production behavior only.

ASG requirement:

- Every web and worker instance in a region must share the same Redis endpoint.
- Recommended production pattern: ElastiCache Redis with TLS and security groups scoped to app instances.
- If self-hosted Redis is used temporarily, it must be one shared regional service, not a container on each ASG node.

Guardrail:

- `scripts/dr/check-asg-multi-instance-readiness.mjs` requires ASG web-node mode to use required shared `REDIS_URL` and `REDIS_TLS=true`.

## B. MinIO And Object Storage

Evidence:

- Object storage uses AWS SDK S3 client in `backend/src/services/objectStorageService.ts`.
- Production startup refuses to run without object storage.
- Incident and support uploads stage through Multer local disk, then upload to object storage and remove local files when object storage is configured.
- Compliance packs now upload generated zip buffers to object storage when configured and record `storageMode` in job summary. Local disk remains only as fallback for non-production/degraded recovery.
- `docker-compose.yml` still defines a local MinIO service and `minio_data` volume.
- Regional env examples now keep `OBJECT_STORAGE_ENDPOINT`, `OBJECT_STORAGE_ACCESS_KEY`, and `OBJECT_STORAGE_SECRET_KEY` empty for S3/default credentials.
- Operator evidence confirms Mumbai and Cape Town use regional S3/default credentials with `endpoint=null` and `mode=default-credentials`.

Residual risk:

- MinIO per ASG node is unsafe because uploads and generated artifacts would be visible only on the node that received the request.
- `docker-compose.asg-web.yml` avoids local MinIO entirely; the legacy MinIO service remains only for local/legacy Compose paths.

ASG requirement:

- Use shared S3 or a managed S3-compatible regional endpoint.
- Prefer IAM instance-profile access with no static object-storage credentials on EC2.
- If a custom endpoint is used, it must be external/shared and HA enough for the region.

ASG requirement:

- ASG launch templates must use `docker-compose.asg-web.yml` and regional S3/default credentials.
- Do not use the legacy local MinIO service in ASG web nodes.

## C. Database Migrations

Evidence:

- Prisma migration scripts exist in `backend/package.json`.
- Runtime image defaults `RUN_DB_MIGRATIONS_ON_START=false`.
- Startup migration command is gated in `backend/docker/start-runtime.sh`.
- Existing operator docs use `npx prisma migrate deploy` as an explicit step.

Risk:

- If `RUN_DB_MIGRATIONS_ON_START=true` is set in ASG user data or environment, every replacing instance may attempt migration at boot.

ASG requirement:

- Run migrations once as an explicit release step before instance refresh.
- Keep web and worker boot environments at `RUN_DB_MIGRATIONS_ON_START=false`.
- For rolling deploys, require backward-compatible migrations or a documented expand/contract plan.

## D. Background Workers And Cron

Evidence:

- Web backend starts background workers only when `RUN_BACKGROUND_WORKERS` parses true.
- Compose explicitly disables background workers on backend and keeps the separate `worker` service behind the `worker` profile.
- `docker-compose.asg-web.yml` contains no worker service.
- Worker starts security event outbox, audit outbox, compliance pack scheduler, print reconcilers, analytics rollups, and hot event partition maintenance.
- Several recurring workers use Redis leases through `withDistributedLease`.
- Compliance pack scheduling has a process-local `lastRunStamp` and is not fully lease-wrapped, so it must stay disabled unless separately approved.
- Operator evidence confirms current regional worker containers run with `RUN_BACKGROUND_WORKERS=true` and `COMPLIANCE_PACK_SCHEDULER_ENABLED=false`.
- Legacy EC2 docs include local certbot cron for the single-node Nginx path.

Risk:

- If ASG web nodes start workers, singleton jobs may duplicate.
- If multiple worker containers run without full distributed locks, scheduled compliance packs and maintenance may duplicate.

ASG requirement:

- Web ASG nodes must run `RUN_BACKGROUND_WORKERS=false`.
- ASG web nodes must use `docker-compose.asg-web.yml`:

```bash
docker compose -f docker-compose.asg-web.yml up -d --build backend frontend
```

- Existing standalone regional EC2 hosts that intentionally own the singleton worker must opt in to the worker profile:

```bash
docker compose --profile worker up -d --build backend worker frontend
```

- Run exactly one worker container per region for now.
- Keep `COMPLIANCE_PACK_SCHEDULER_ENABLED=false` unless a separate approval adds a distributed lock or other singleton control for that scheduler.
- Do not assume worker horizontal scaling is safe.
- CTO recommendation: split workers into named process roles: `outbox`, `print-reconcile`, `analytics`, `maintenance`, and `compliance-scheduler`, each with Redis/database locking and independent concurrency.

## E. Filesystem Writes

Evidence:

- Incident uploads stage to `backend/uploads/incidents`.
- Support screenshots stage to `backend/uploads/support-issues`.
- Compliance packs used to persist to `backend/uploads/compliance-packs`; generated packs now prefer object storage.
- Local print agent writes to OS temp and user home state. That agent is workstation-side and not part of the web ASG.
- Docker/Nginx writes logs to container logging and certbot volumes in the current EC2 path.

Risk:

- Persistent uploads, PDFs, reports, QR artifacts, or generated exports on EC2 instance-local disk will be lost or invisible across nodes.

ASG requirement:

- Treat local disk as ephemeral staging only.
- Keep persistent artifacts in object storage and persistent metadata in Postgres.
- Do not mount per-instance MinIO as the production artifact source.

## F. Secrets Injection And Bootstrap

Evidence:

- Backend loads `.env` via dotenv and Compose uses `env_file: ./backend/.env`. Docker Compose interpolation happens before service `env_file` values are applied, so ASG bootstrap writes the project `.env` as a 0600 root/backend union for normal post-bootstrap diagnostics and also renders a temporary union env file for explicit `docker compose --env-file` bootstrap commands.
- Production startup validates many required secret and URL values without printing secret values.
- `scripts/dr/bootstrap-asg-web-node.sh` fetches env values from SSM Parameter Store with `--with-decryption`, writes project `.env` and `backend/.env` with `0600` permissions, and does not print secret values.
- The bootstrap script validates required manifest keys, rejects MinIO secrets, and forces ASG-safe values before starting containers.
- Missing required SSM values are reported as parameter names plus full paths, for example `DATABASE_URL (/mscqr/prod/ap-south-1/asg-web/DATABASE_URL)`, without printing values. Required parameters that exist but are empty fail before Compose with the same key/path-only diagnostics.
- The bootstrap script starts only ASG web mode:

```bash
docker compose -f docker-compose.asg-web.yml up -d --build --remove-orphans backend frontend
```

- Health validation is through the frontend/Nginx path: `http://127.0.0.1/healthz` and `http://127.0.0.1/api/health/ready`.
- Readiness must report `database.ready=true`, `redis.configured=true`, `redis.ready=true`, `objectStorage.configured=true`, and `objectStorage.ready=true`.
- On startup or readiness failure, bootstrap prints no-secret diagnostics: Docker container status, Compose ps using the generated `--env-file`, backend/frontend inspect state, a sanitized backend readiness dependency summary, local health curls, and backend/frontend log tails.
- `ops/aws/iam/dr/asg-web-instance-profile-policy.template.json` defines the instance-profile permissions for SSM, scoped KMS decrypt, regional S3 artifact access, and ECR image pull.

SSM Parameter Store prefixes:

- Mumbai: `/mscqr/prod/ap-south-1/asg-web/`
- Cape Town: `/mscqr/prod/af-south-1/asg-web/`

Bootstrap commands:

```bash
scripts/dr/bootstrap-asg-web-node.sh mumbai ap-south-1
scripts/dr/bootstrap-asg-web-node.sh capetown af-south-1
```

Required production env categories:

- Database: `DATABASE_URL`.
- Auth/session/signing: `JWT_SECRET_CURRENT` or `JWT_SECRET`, QR signing keys or managed signer refs, token hash secrets, IP hash salt, customer verify secrets, scan fingerprint secret, printer SSE signing secret, incident hash salt, MFA encryption key.
- Redis: `REDIS_URL` or `REDIS_HOST`/`REDIS_PORT` plus optional TLS/password settings.
- Object storage: `OBJECT_STORAGE_BUCKET`, `OBJECT_STORAGE_REGION` or `AWS_REGION`, optional external endpoint, optional static credentials only for custom endpoints.
- Public URLs/CORS: `PUBLIC_SCAN_WEB_BASE_URL`, `PUBLIC_VERIFY_WEB_BASE_URL`, `PUBLIC_ADMIN_WEB_BASE_URL`, `WEB_APP_BASE_URL`, `CORS_ORIGIN`.
- Cookies: `COOKIE_SECURE=true` in production.
- SMTP: `SMTP_HOST`, `SMTP_USER`, and `SMTP_PASS` are required for production email. `SMTP_FROM` is optional but recommended; the backend can boot without it and uses the authenticated SMTP mailbox as the From address when the override is absent.

ASG requirement:

- Use an IAM instance profile with least-privilege read access to the region-specific SSM Parameter Store path.
- Provide that profile explicitly through `ASG_WEB_INSTANCE_PROFILE_ARN` or `ASG_WEB_INSTANCE_PROFILE_NAME`; do not copy the source EC2 instance profile by default.
- Test the final ASG web instance profile from an EC2 role before ASG apply by running the bootstrap in render-only mode and confirming it can fetch the approved SSM prefix without printing values.
- Render container environment at boot without logging values.
- Fail boot if any required value is missing.
- Before retry, list SSM parameter names only and compare them with `documents/ops/aws-asg-web-ssm-parameter-manifest.json`; do not fetch or print parameter values.
- Do not rely on SSH/manual edits to `backend/.env` for new ASG instances.
- Keep `OBJECT_STORAGE_ENDPOINT`, `OBJECT_STORAGE_ACCESS_KEY`, and `OBJECT_STORAGE_SECRET_KEY` empty.
- Keep `OBJECT_STORAGE_FORCE_PATH_STYLE=false`, `REDIS_TLS=true`, `RUN_BACKGROUND_WORKERS=false`, `RUN_DB_MIGRATIONS_ON_START=false`, and `COMPLIANCE_PACK_SCHEDULER_ENABLED=false`.
- `QR_SIGN_PRIVATE_KEY`, `QR_SIGN_PUBLIC_KEY`, and `QR_SIGN_ACTIVE_KEY_VERSION` must be present and non-empty in SSM because `docker-compose.asg-web.yml` interpolates them before the backend container starts. The value format remains the existing backend contract: base64-wrapped PEM or escaped-newline PEM, with no secret values printed by bootstrap or checks.
- Recommended email sender override for Mumbai, if the SMTP provider authorizes it: `/mscqr/prod/ap-south-1/asg-web/SMTP_FROM`. This key is optional for boot, but should be created before email-delivery validation.

Safe names-only SSM preflight:

```bash
aws ssm describe-parameters \
  --region ap-south-1 \
  --parameter-filters "Key=Path,Option=Recursive,Values=/mscqr/prod/ap-south-1/asg-web/" \
  --query 'Parameters[].Name' \
  --output text | tr '\t' '\n' | sort
```

## G. Docker Startup And Bootstrap Repeatability

Evidence:

- Frontend and backend Dockerfiles build deterministic images.
- Backend startup is simple and repeatable when env exists.
- Legacy Compose topology includes local Redis/MinIO and local certbot volumes.
- ASG web-node Compose topology excludes local Redis, MinIO, and worker services.
- Regional ASG launch-template scripts exist as plan/apply scaffolding, but ASG creation is out of scope and not run by this audit.
- ASG UserData no longer assumes a pre-baked application host. For the no-DNS validation path it can start from a plain Ubuntu 22.04 AMI, install/check required packages, install Docker Compose v2 even when the apt plugin package is unavailable, install AWS CLI for SSM Parameter Store access, install Node.js/npm for the bootstrap script, clone or refresh the repo, and invoke the SSM-backed ASG web bootstrap.

ASG bootstrap checklist:

- Install/check `git`, `ca-certificates`, `curl`, `docker.io`, and Docker Compose v2 before repository bootstrap.
- If `docker compose version` is missing after Docker starts, try `apt-get install -y docker-compose-plugin`; if apt cannot supply it, install the pinned Compose v2 binary under `/usr/local/lib/docker/cli-plugins/docker-compose` using architecture mapping for `x86_64`/`amd64` and `aarch64`/`arm64`.
- Install/check AWS CLI before the SSM bootstrap. If `aws --version` is missing, try `apt-get install -y awscli`; if apt cannot supply a working CLI, install AWS CLI v2 from the official installer at `https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip` after installing `curl`, `unzip`, and `ca-certificates`.
- Install/check Node.js and npm before the SSM bootstrap. The repo engine contract is `node >=24 <27` and `npm >=11`, so UserData configures the pinned NodeSource `node_24.x` repository and installs `nodejs` when the host runtime is missing or out of range.
- Use `ASG_REPO_URL` to clone the repository if `ASG_REPO_DIR` is missing.
- Use `ASG_REPO_BRANCH` to fetch/reset the checkout if `ASG_REPO_DIR` already contains a git checkout.
- Fail clearly without deleting anything if `ASG_REPO_DIR` exists but is not a git checkout.
- Pull or build the approved image for the exact commit SHA.
- Fetch environment from SSM Parameter Store through instance profile using `scripts/dr/bootstrap-asg-web-node.sh`.
- Render project `.env`, `backend/.env`, and a temporary Compose interpolation env file from SSM. The project `.env` and temp Compose env both contain the root/backend union so required variables such as `QR_SIGN_PRIVATE_KEY` and `QR_SIGN_ACTIVE_KEY_VERSION` are visible to Compose interpolation during bootstrap and to later operator `docker compose ps` diagnostics, without printing values.
- Include launch-template `UserData` that logs only non-secret bootstrap status to `/var/log/mscqr-asg-bootstrap.log`.
- Keep launch-template `IamInstanceProfile` explicit and supplied by `ASG_WEB_INSTANCE_PROFILE_ARN` or `ASG_WEB_INSTANCE_PROFILE_NAME`.
- Set launch-template public IP behavior explicitly with `ASG_ASSOCIATE_PUBLIC_IP=true` or `ASG_ASSOCIATE_PUBLIC_IP=false`.
- Use `ASG_KEY_NAME=mscqr-prod-mumbai` for the Mumbai no-DNS debug retry so failed nodes can be inspected over SSH.
- Use `ASG_REPO_URL=https://github.com/T-ej2003/genuine-scan-main.git`, `ASG_REPO_BRANCH=main`, and `ASG_REPO_DIR=/home/ubuntu/genuine-scan-main` for the Mumbai no-DNS debug retry.
- Set `RUN_DB_MIGRATIONS_ON_START=false`.
- Set backend `RUN_BACKGROUND_WORKERS=false` on web nodes.
- Point `REDIS_URL` to shared regional Redis.
- Point object storage to shared S3/managed endpoint.
- Start only frontend/backend containers on web ASG nodes with `docker-compose.asg-web.yml` and the generated `--env-file` interpolation env.
- Use backend `/health/live` for the backend container healthcheck to avoid blocking frontend/Nginx startup on deep dependencies. Keep `/api/health/ready` as the bootstrap and operator smoke gate so database, Redis, and object storage failures are still exposed and fail the node bootstrap.
- Register only after `/api/health/ready` is healthy.
- Ship logs to CloudWatch; do not depend on instance-local log retention.

## H. Health Check Grace Period

Semantics:

- `/healthz`: shallow liveness/status. Use this for Nginx/frontend and basic process checks.
- `/api/health/ready`: backend dependency readiness. It validates database, Redis, and object storage in production.

Current Compose health:

- Backend container healthcheck calls backend `/health/ready`.
- Frontend healthcheck calls Nginx `/healthz`.
- Nginx proxies `/api/health/*` to backend `/health/*`.

Recommended ALB/ASG settings before apply:

- ALB target path for frontend target group: `/healthz`.
- Separate operator smoke path after target is healthy: `/api/health/ready`.
- Health check interval: 15 seconds.
- Timeout: 5 seconds for `/healthz`; 10 seconds for readiness smoke.
- Healthy threshold: 2.
- Unhealthy threshold: 3.
- ASG health check grace period: 180 seconds initially, then tune from measured boot evidence.
- Default instance warmup: 180 seconds.

## I. Rolling Deploy Behavior

Committed policy:

- `documents/ops/aws-asg-rolling-deploy-policy.md`
- `documents/ops/aws-asg-rolling-deploy-policy.checklist.json`
- `scripts/dr/generate-asg-apply-plan.sh`
- `scripts/dr/apply-asg-launch-template-approved.sh`

Launch-template requirements:

- `IamInstanceProfile` must come from explicit `ASG_WEB_INSTANCE_PROFILE_ARN` or `ASG_WEB_INSTANCE_PROFILE_NAME`.
- `UserData` must be base64 encoded and must run `scripts/dr/bootstrap-asg-web-node.sh "$TARGET_REGION_GROUP" "$AWS_REGION"` from `ASG_REPO_DIR`.
- `UserData` must install/check Git, Docker, Docker Compose, AWS CLI, Node.js, and npm before app bootstrap, with an apt `docker-compose-plugin` attempt, a pinned manual Compose v2 plugin fallback under `/usr/local/lib/docker/cli-plugins/docker-compose`, an apt `awscli` attempt, an official AWS CLI v2 installer fallback, and pinned-major Node.js 24 setup.
- `UserData` must tee `scripts/dr/bootstrap-asg-web-node.sh` output to `/var/log/mscqr-asg-bootstrap.log` and cloud-init console output while preserving the bootstrap script exit code without relying on `pipefail`.
- `UserData` must clone `ASG_REPO_URL` into `ASG_REPO_DIR` when missing; if `ASG_REPO_DIR` already contains a git checkout, it must fetch/reset `ASG_REPO_BRANCH`; if the path exists but is not a git checkout, it must fail clearly and must not delete it automatically.
- `UserData` must log to `/var/log/mscqr-asg-bootstrap.log`, avoid printing secret values, and never touch Route 53 or production DNS.
- `UserData` must mirror non-secret status/failure lines to cloud-init console output and include a failure trap with safe diagnostics only.
- `MetadataOptions.HttpTokens` must be `required`.
- `ImageId` and `InstanceType` must be present.
- `ASG_KEY_NAME` is optional generally; when set it must become `KeyName`, and when omitted `KeyName` must be absent.
- `ASG_REPO_URL` is required for self-sufficient ASG web-node bootstrap and must not contain whitespace or embedded credentials.
- `ASG_REPO_BRANCH` defaults to `main`; `ASG_REPO_DIR` defaults to `/home/ubuntu/genuine-scan-main`.
- `ASG_ASSOCIATE_PUBLIC_IP=false` must use top-level `SecurityGroupIds=[SOURCE_SECURITY_GROUP]` and no `NetworkInterfaces`.
- `ASG_ASSOCIATE_PUBLIC_IP=true` must use `NetworkInterfaces[0].AssociatePublicIpAddress=true` with `Groups=[SOURCE_SECURITY_GROUP]` and no top-level `SecurityGroupIds`.

Mumbai retry note:

- The first failed Mumbai ASG attempt produced instances that failed ALB health checks, and console output showed bootstrap/network credential failures.
- The later Mumbai no-DNS attempt launched instances, but the selected AMI was not app-baked: `/home/ubuntu/genuine-scan-main` was missing, Docker was not installed/running, and UserData failed at repo-directory preflight. The next retry used the self-sufficient package and repo bootstrap path.
- Latest Mumbai no-DNS evidence: EC2 instances launched successfully with public IP, `KeyName`, and instance profile; `git` was already installed; Docker installed successfully and the Docker service became active; `docker-compose-plugin` was unavailable from apt; `docker compose` returned `docker: unknown command: docker compose`; bootstrap failed during the Docker Compose check before the repo clone; ALB target health failed because app containers never started; a later SSH attempt returned `PublicIp=None` because ASG had already replaced the node; the original Mumbai EC2 remained healthy; no DNS cutover happened.
- The fix is a manual pinned Docker Compose v2 plugin fallback after the apt plugin attempt.
- Latest retry evidence: the Docker Compose fallback succeeded, Docker Compose verification completed, the repo bootstrap reached `running bootstrap script`, and `scripts/dr/bootstrap-asg-web-node.sh` existed. Failure moved into the bootstrap script, likely because AWS CLI was missing for SSM fetches or because detailed bootstrap output was only redirected into `/var/log/mscqr-asg-bootstrap.log` on a terminated node. The fix adds AWS CLI as a UserData prerequisite and mirrors bootstrap output into cloud-init console while keeping the same non-secret log file.
- Latest Node prerequisite evidence: instances reached repo HEAD `c97edfe`, AWS CLI installed from apt and verified, then `scripts/dr/bootstrap-asg-web-node.sh` failed with `ERROR: node is required.` New ASG targets reached EC2/ASG healthy states but failed ALB health checks because app bootstrap never completed; the old manual Mumbai target remained healthy and no DNS cutover happened. The fix adds Node.js 24/npm 11 host prerequisite checks before running the bootstrap script.
- Latest SSM env-render evidence: fresh ASG nodes passed Git, Docker, Docker Compose, AWS CLI, Node.js 24, npm 11, repo clone, and bootstrap handoff, then failed while fetching `/mscqr/prod/ap-south-1/asg-web/` with `backendEnv missing required SSM parameter(s): SMTP_FROM`. Source review showed `SMTP_FROM` is a recommended authorized sender override, not a backend startup requirement; the backend falls back to `SMTP_USER` as the From address when absent. The ASG manifest now makes `SMTP_FROM` optional/recommended and missing required errors include the full SSM parameter path.
- Latest Compose interpolation evidence: fresh ASG nodes rendered env files successfully and consumed SSM parameter names including `/mscqr/prod/ap-south-1/asg-web/QR_SIGN_PRIVATE_KEY`, but Compose failed before container creation with `services.backend.environment.QR_SIGN_PRIVATE_KEY` missing. Root cause: `QR_SIGN_PRIVATE_KEY` was written to `backend/.env`, while Compose interpolation runs before service `env_file` loading. The fix renders the project `.env` and temporary bootstrap env as root/backend union files, invokes `docker compose --env-file` during bootstrap, and still writes `backend/.env` for the backend container without logging values.
- Latest ASG health evidence: fresh ASG nodes now build backend/frontend images and start the backend. The backend logs `Server running on http://localhost:4000`, QR signing profile is ready with `keyVersion: v1`, and workers are disabled, but backend `/health/ready` returns 503. Because frontend depended on backend `service_healthy` and backend health used deep readiness, the frontend stayed `Created`, host port 80 never listened, and the ALB `/healthz` target health failed. The fix changes backend container health to `/health/live`, starts Nginx after backend process liveness, keeps bootstrap gated on `/api/health/ready`, and adds no-secret diagnostics that identify the true dependency readiness blocker.
- Mumbai selected public subnets currently have `MapPublicIpOnLaunch=false`, so the next no-DNS Mumbai retry should use `ASG_ASSOCIATE_PUBLIC_IP=true`.
- The next no-DNS Mumbai retry should also use `ASG_KEY_NAME=mscqr-prod-mumbai` to make failed nodes inspectable.
- The next no-DNS Mumbai retry should set `ASG_REPO_URL=https://github.com/T-ej2003/genuine-scan-main.git`, `ASG_REPO_BRANCH=main`, and `ASG_REPO_DIR=/home/ubuntu/genuine-scan-main`.
- Preferred production design: move ASG web nodes to private app subnets with NAT Gateway or VPC endpoints for SSM, EC2Messages, SSMMessages, S3, ECR, CloudWatch Logs, and Git access, then use `ASG_ASSOCIATE_PUBLIC_IP=false`.

Exact Mumbai no-DNS retry inputs:

```bash
TARGET_REGION_GROUP=mumbai
AWS_REGION=ap-south-1
SOURCE_INSTANCE_ID=i-04ae3b689ab72a68a
SOURCE_AMI=ami-07216ac99dc46a187
SOURCE_INSTANCE_TYPE=t3.medium
SOURCE_SECURITY_GROUP=sg-0771ea7e59f7a49d4
TARGET_GROUP_ARN=arn:aws:elasticloadbalancing:ap-south-1:368992683803:targetgroup/mscqr-mumbai-frontend-tg/68982ccd4d8c26c1
ASG_WEB_INSTANCE_PROFILE_ARN=arn:aws:iam::368992683803:instance-profile/mscqr-asg-web-instance-profile-aps1
ASG_ASSOCIATE_PUBLIC_IP=true
ASG_KEY_NAME=mscqr-prod-mumbai
ASG_REPO_URL=https://github.com/T-ej2003/genuine-scan-main.git
ASG_REPO_BRANCH=main
ASG_REPO_DIR=/home/ubuntu/genuine-scan-main
ROLLBACK_ALARM_NAMES_CSV=MSCQR-mumbai-ALB-5XX,MSCQR-mumbai-Target-5XX,MSCQR-mumbai-TargetResponseTime-p95,MSCQR-mumbai-UnhealthyHosts
MIN_SIZE=2
DESIRED_CAPACITY=2
MAX_SIZE=4
```

Add only for protected apply, not plan generation:

```bash
CONFIRM_ASG_APPLY=I_APPROVE_REGIONAL_ASG_CREATE_AND_ATTACH
```

Approved first-rollout values:

- Use ALB target deregistration delay of 60 seconds.
- Use `ELB` health checks with 180 second ASG grace period.
- Use 180 second default instance warmup.
- Use instance refresh minimum healthy capacity at 100 percent for desired capacity 2.
- Use maximum healthy percentage 150 if supported by the selected rollout path.
- Use checkpoints at 50 percent and 100 percent with 300 second wait per checkpoint.
- Do not run migrations during instance boot.
- Roll out web first with `RUN_BACKGROUND_WORKERS=false`.
- Promote or restart singleton worker only after web readiness is green.
- Roll back by canceling instance refresh, keeping the previous launch template version available, and restoring healthy target count before removing any new unhealthy instance.
- Capture `/healthz`, `/api/health/ready`, ALB target health, and app version evidence per batch.
- Keep production DNS on London EC2 during the first ASG rollout and replacement-instance drill.

## Current Go/No-Go

Conditionally ready for a first controlled ASG rollout with no production DNS cutover.

Worker topology is conditionally proven for ASG web nodes: web nodes have an explicit worker-free Compose file, the HTTP backend is worker-disabled, the standalone worker is an intentional one-per-region profile, compliance scheduling is disabled, and worker horizontal scaling is not assumed safe.

Secrets/bootstrap is conditionally proven at repository level: the SSM manifest, bootstrap script, forced safety settings, SSM prefixes, launch-template `UserData`, optional debug `KeyName`, explicit instance-profile input, health validation, and instance-profile IAM template are committed. This still needs a real replacement-instance drill before production use.

Rolling deploy policy is conditionally proven at repository level: the contract document, machine-readable checklist, plan/apply script gates, launch-template validation, rollback criteria, and replacement-instance drill procedure are committed.

Exact remaining live test:

- Create and attach the regional ASG with `min=2 desired=2 max=4`.
- Keep production DNS on London EC2.
- Verify at least 2 healthy targets on the regional ALB.
- Run the documented replacement-instance drill and record CloudWatch plus target-health evidence.

No-go for production DNS cutover until that live drill passes and the regional rollback path is practiced cleanly.

## Validation

Run:

```bash
node scripts/dr/check-asg-multi-instance-readiness.mjs
node scripts/dr/check-asg-compose-interpolation.mjs --docker-compose-config
/bin/sh -n scripts/dr/*.sh
npm run check:aws-dr-safety
npm run verify:guardrails
npm run check:documents
git diff --check
```

The validation script is static. It does not call AWS, mutate RDS/S3, create ASGs, change DNS, or delete resources.
