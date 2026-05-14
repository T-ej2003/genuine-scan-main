# AWS ASG Multi-Instance Readiness

Last updated: 2026-05-14

ASG_STATUS=BLOCKED

Do not create ASGs. Do not attach instances to ASGs. Do not perform production DNS cutover. Do not mutate RDS data. Do not delete AWS resources. This document is a code, configuration, and runbook audit for preparing MSCQR to run safely behind regional ALBs with two or more EC2 instances.

## Executive Verdict

MSCQR is not yet safe to scale to two or more EC2 instances per region.

The app has several good production controls already:

- Production startup refuses to run without Redis coordination.
- Production startup refuses to run without object storage.
- Backend container startup defaults `RUN_DB_MIGRATIONS_ON_START=false`.
- Docker Compose disables background workers in the HTTP backend with `RUN_BACKGROUND_WORKERS=false`.
- A separate worker process exists for schedulers, outbox flushing, reconciliation, analytics rollups, and hot event maintenance.
- `/healthz` exists for shallow app liveness and `/api/health/ready` reaches backend dependency readiness through Nginx.

The remaining blockers are operational and state-topology blockers:

- Compose still provisions local Redis and local MinIO. If copied into an ASG node-per-instance model, each node would have isolated coordination and object data.
- The ASG launch path for secrets is not proven. New instances must receive the same required secrets through IAM-backed SSM or Secrets Manager, not manual terminal edits.
- Worker singleton behavior is not fully proven for every scheduled job. Web ASG nodes must not run background workers.
- Rolling deployment policy is not applied or tested.
- Some upload flows stage files on local disk before object-storage upload. That is acceptable only as short-lived temp/staging, not as persistent state.

## Architecture Evidence

Repository shape:

- Frontend: Vite/React static bundle served by Nginx.
- Backend: Express/Prisma service in `backend/src/index.ts`.
- Worker: `backend/src/worker.ts` using the same backend image with a worker entrypoint.
- Local orchestration: `docker-compose.yml` with `frontend`, `backend`, `worker`, `redis`, `minio`, and `minio-init`.
- Database: Prisma/PostgreSQL through `DATABASE_URL`.
- Object storage: S3-compatible client in `backend/src/services/objectStorageService.ts`.

Runtime defaults that matter for ASG:

- `backend/Dockerfile` sets `RUN_DB_MIGRATIONS_ON_START=false`.
- `backend/docker/start-runtime.sh` runs `npx prisma migrate deploy` only when `RUN_DB_MIGRATIONS_ON_START=true`.
- `docker-compose.yml` sets backend `RUN_BACKGROUND_WORKERS: "false"`.
- `docker-compose.yml` sets worker `RUN_BACKGROUND_WORKERS: "true"`.
- `docker-compose.yml` defaults `REDIS_URL` to `redis://redis:6379/0`.
- `docker-compose.yml` includes local `minio_data` and `redis_data` volumes.

## A. Redis And Sessions

Evidence:

- Redis is configured by `REDIS_URL` or `REDIS_HOST`/`REDIS_PORT` in `backend/src/services/redisService.ts`.
- Production startup in `backend/src/index.ts` refuses to start when Redis is not configured.
- Public rate limits use `rate-limit-redis` when Redis is configured.
- Incident report rate limits, versioned cache invalidation, audit/notification pub-sub, and distributed leases use Redis when configured.
- Auth sessions are JWT/cookie-backed, not Express in-memory sessions. No `express-session` MemoryStore was found in backend source.

Risk:

- Local Redis per EC2 node would split rate limits, leases, cache invalidation, notifications, and pub-sub.
- Any in-process fallback is for local/non-production behavior only.

ASG requirement:

- Every web and worker instance in a region must share the same Redis endpoint.
- Recommended production pattern: ElastiCache Redis with TLS and security groups scoped to app instances.
- If self-hosted Redis is used temporarily, it must be one shared regional service, not a container on each ASG node.

Guardrail:

- `scripts/dr/check-asg-multi-instance-readiness.mjs` keeps ASG blocked while local Redis defaults remain and shared `REDIS_URL` evidence is not committed.

## B. MinIO And Object Storage

Evidence:

- Object storage uses AWS SDK S3 client in `backend/src/services/objectStorageService.ts`.
- Production startup refuses to run without object storage.
- Incident and support uploads stage through Multer local disk, then upload to object storage and remove local files when object storage is configured.
- Compliance packs now upload generated zip buffers to object storage when configured and record `storageMode` in job summary. Local disk remains only as fallback for non-production/degraded recovery.
- `docker-compose.yml` still defines a local MinIO service and `minio_data` volume.
- `.env.production.mumbai.example` currently documents `OBJECT_STORAGE_ENDPOINT=http://minio:9000`.

Risk:

- MinIO per ASG node is unsafe because uploads and generated artifacts would be visible only on the node that received the request.

ASG requirement:

- Use shared S3 or a managed S3-compatible regional endpoint.
- Prefer IAM instance-profile access with no static object-storage credentials on EC2.
- If a custom endpoint is used, it must be external/shared and HA enough for the region.

ASG blocker:

- `LOCAL_MINIO_IN_COMPOSE` remains open until regional production config proves shared object storage.

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
- Compose explicitly disables background workers on backend and runs a separate `worker` service.
- Worker starts security event outbox, audit outbox, compliance pack scheduler, print reconcilers, analytics rollups, and hot event partition maintenance.
- Several recurring workers use Redis leases through `withDistributedLease`.
- Compliance pack scheduling has a process-local `lastRunStamp` and is not fully lease-wrapped.
- Legacy EC2 docs include local certbot cron for the single-node Nginx path.

Risk:

- If every ASG web node starts workers, singleton jobs may duplicate.
- If multiple worker containers run without full distributed locks, scheduled compliance packs and maintenance may duplicate.

ASG requirement:

- Web ASG nodes must run `RUN_BACKGROUND_WORKERS=false`.
- Run workers as one separate singleton per region until every scheduler is lease-protected.
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

## F. Secrets Injection

Evidence:

- Backend loads `.env` via dotenv and Compose uses `env_file: ./backend/.env`.
- Production startup validates many required secret and URL values without printing secret values.
- No committed ASG bootstrap path proves that a fresh EC2 instance can fetch the same secrets automatically.

Required production env categories:

- Database: `DATABASE_URL`.
- Auth/session/signing: `JWT_SECRET_CURRENT` or `JWT_SECRET`, QR signing keys or managed signer refs, token hash secrets, IP hash salt, customer verify secrets, scan fingerprint secret, printer SSE signing secret, incident hash salt, MFA encryption key.
- Redis: `REDIS_URL` or `REDIS_HOST`/`REDIS_PORT` plus optional TLS/password settings.
- Object storage: `OBJECT_STORAGE_BUCKET`, `OBJECT_STORAGE_REGION` or `AWS_REGION`, optional external endpoint, optional static credentials only for custom endpoints.
- Public URLs/CORS: `PUBLIC_SCAN_WEB_BASE_URL`, `PUBLIC_VERIFY_WEB_BASE_URL`, `PUBLIC_ADMIN_WEB_BASE_URL`, `WEB_APP_BASE_URL`, `CORS_ORIGIN`.
- Cookies: `COOKIE_SECURE=true` in production.
- SMTP: SMTP user/pass aliases used by backend.

ASG requirement:

- Use an IAM instance profile with least-privilege read access to SSM Parameter Store or Secrets Manager paths.
- Render container environment at boot without logging values.
- Fail boot if any required value is missing.
- Do not rely on SSH/manual edits to `backend/.env` for new ASG instances.

## G. Docker Startup And Bootstrap Repeatability

Evidence:

- Frontend and backend Dockerfiles build deterministic images.
- Backend startup is simple and repeatable when env exists.
- Current Compose topology includes local Redis/MinIO and local certbot volumes.
- Regional ASG launch-template scripts exist as plan/apply scaffolding, but ASG creation is out of scope and not run by this audit.

ASG bootstrap checklist:

- Install Docker and the Compose plugin from a pinned or approved source.
- Pull or build the approved image for the exact commit SHA.
- Fetch environment from SSM/Secrets Manager through instance profile.
- Set `RUN_DB_MIGRATIONS_ON_START=false`.
- Set backend `RUN_BACKGROUND_WORKERS=false` on web nodes.
- Point `REDIS_URL` to shared regional Redis.
- Point object storage to shared S3/managed endpoint.
- Start only frontend/backend containers on web ASG nodes.
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

Required policy before ASG apply:

- Use ALB target deregistration delay of at least 60 seconds.
- Instance refresh should keep minimum healthy capacity at 100 percent for desired capacity 2.
- Maximum unavailable should be 1 instance.
- Do not run migrations during instance boot.
- Roll out web first with `RUN_BACKGROUND_WORKERS=false`.
- Promote or restart singleton worker only after web readiness is green.
- Roll back by canceling instance refresh and keeping the previous launch template version available.
- Capture `/healthz`, `/api/health/ready`, ALB target health, and app version evidence per batch.

## Current Go/No-Go

No-go for ASG create/attach.

The app is conditionally close from a code perspective after the compliance pack object-storage hardening, but operations evidence is not enough to run multiple EC2 instances safely. Re-audit only after shared Redis, shared object storage, secret injection, worker topology, bootstrap, health grace, and rolling deploy policy are all proven in a regional test path.

## Validation

Run:

```bash
node scripts/dr/check-asg-multi-instance-readiness.mjs
npm run check:aws-dr-safety
npm run verify:guardrails
npm run check:documents
git diff --check
```

The validation script is static. It does not call AWS, mutate RDS/S3, create ASGs, change DNS, or delete resources.
