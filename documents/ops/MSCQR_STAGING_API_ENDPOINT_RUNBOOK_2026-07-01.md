# MSCQR Staging API Endpoint Runbook - 2026-07-01

## Scope

This runbook prepares and validates a real MSCQR staging API endpoint in AWS London for RLS staging validation. It is planning/readiness only until an operator explicitly creates resources through reviewed AWS/IaC changes.

Hard limits:

- No production AWS resource mutation.
- No production deployment.
- No production database use.
- No real secrets committed.
- No production RLS.
- No global/table RLS.
- No `www.mscqr.com`, `mscqr.com`, or default `*.mscqr.com` staging target.

## Inputs To Collect

Record names and hosts only. Do not paste secret values into docs, issues, logs, or evidence.

| Item | Required value | Forbidden value pattern |
| --- | --- | --- |
| AWS region | `eu-west-2` | Other region unless reviewed |
| Staging base URL | Non-MSCQR staging URL | `mscqr.com`, `*.mscqr.com`, `prod`, `production` |
| Staging API base URL | Non-production API URL ending in `/api` if used by smoke | `https://www.mscqr.com/api` |
| ECS cluster | Staging cluster | `mscqr-prod-euw2-main` |
| ECS backend service | Staging backend service | Production backend service |
| Task definition | Staging backend task family/revision | Production task revision without env replacement |
| Database host/proxy | Staging DB/proxy | `mscqr-prod-db`, `mscqr-prod-db-proxy` |
| Redis host/URL | Staging Redis or isolated namespace | `mscqr-redis-euw2-primary` |
| Object storage | Staging bucket/prefix | Production artifact bucket/prefix |

## Phase 1: Preflight Review

1. Confirm the target account/region and operator identity.
2. Confirm no GitHub staging variable points at production:
   - `STAGING_SMOKE_BASE_URL`
   - `STAGING_SMOKE_API_BASE_URL`
   - `STAGING_BASE_URL`
3. Run the repo-only readiness helper:

```sh
node scripts/check-staging-endpoint-readiness.mjs --dry-run
```

4. Confirm the RLS collector still refuses production domains:

```sh
node scripts/collect-rls-staging-validation-evidence.mjs --self-check-host-guard
```

5. Confirm the readiness checklist is reviewed:

```sh
node scripts/check-staging-endpoint-readiness.mjs --print-checklist
```

## Phase 2: Build Staging Data Plane

1. Create or identify a non-production VPC/subnet/security-group path in `eu-west-2`.
2. Create staging Postgres:
   - Preferred: fresh RDS instance.
   - Alternative: sanitized snapshot restore.
   - Must not share production write credentials.
3. Apply Prisma migrations to staging only:

```sh
DATABASE_URL="<staging-database-url-from-secret-store>" \
npx prisma migrate deploy --schema backend/prisma/schema.prisma
```

4. Create staging Redis or an explicitly isolated non-production namespace.
5. Create staging object storage bucket/prefix with public access blocked and narrow IAM access.
6. Create staging-only secrets in Secrets Manager or GitHub environment secrets.

## Phase 3: Build Staging Backend Service

1. Use the existing signed ECR image flow, or reuse an already-published digest after verifying provenance.
2. Create a staging backend task definition:
   - Container name: `backend` unless intentionally changed.
   - Image: immutable digest ref.
   - `SENTRY_ENVIRONMENT=staging`.
   - `DATABASE_URL` from staging secret only.
   - Redis and object storage values from staging resources only.
   - Public base URLs pointing only to staging values.
   - RLS route flags all false.
3. Create staging ECS service with desired count `1`.
4. Attach to a staging target group and listener.
5. Do not attach production backend tasks to the staging target group.
6. Do not attach staging tasks to production target groups.

## Phase 4: Endpoint Verification

1. Verify backend health:

```sh
curl -fsS "<staging-base-url>/api/health"
```

If `/api/health` is not the deployed health route, use the actual backend health route verified from the task/ALB health check, such as `/health/live` or `/health/ready`.

2. Verify version when enabled:

```sh
curl -fsS "<staging-base-url>/version"
```

3. Confirm staging DB host from task configuration is not production.
4. Confirm staging Redis/object storage names are not production.
5. Create or verify staging smoke user and safe staging batch data.
6. Run:

```sh
STAGING_BASE_URL="<staging-base-url>" \
node scripts/collect-rls-staging-validation-evidence.mjs --dry-run
```

## Phase 5: GitHub Environment Update

Update GitHub environment `staging` only after Phase 4 passes.

Variables:

- `STAGING_SMOKE_BASE_URL=<reviewed-staging-frontend-or-base-url>`
- `STAGING_SMOKE_API_BASE_URL=<reviewed-staging-api-url>/api`
- `STAGING_BASE_URL=<reviewed-staging-base-url>`
- `AWS_REGION=eu-west-2`
- `STAGING_ECS_CLUSTER=<staging-cluster>`
- `STAGING_ECS_SERVICE=<staging-backend-service>`
- `STAGING_DATABASE_HOST=<staging-db-or-proxy-host>`
- `STAGING_REDIS_URL=<staging-redis-url-or-host>`
- `STAGING_OBJECT_STORAGE_BUCKET=<staging-bucket>`
- `STAGING_OBJECT_STORAGE_PREFIX=<optional-staging-prefix>`

Secrets:

- `STAGING_DATABASE_URL`
- `STAGING_JWT_SECRET_CURRENT`
- `STAGING_QR_SIGN_PRIVATE_KEY`
- `STAGING_QR_SIGN_PUBLIC_KEY`
- `STAGING_QR_SIGN_ACTIVE_KEY_VERSION`
- `STAGING_PRINTER_SSE_SIGN_SECRET_CURRENT`
- Required hash/salt secrets used by the backend.
- `SMOKE_LOGIN_EMAIL` and `SMOKE_LOGIN_PASSWORD` if frontend smoke is enabled.
- `STAGING_AUTH_TOKEN` only in secure operator/GitHub context for RLS collection.

## Phase 6: RLS Baseline

With all RLS flags off:

1. Confirm task definition has:
   - `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED=false`
   - `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED=false`
   - `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED=false`
2. Run collector dry-run.
3. Run the baseline collector with a staging token and staging batch ID:

```sh
STAGING_BASE_URL="<staging-base-url>" \
STAGING_AUTH_TOKEN="<secure-token>" \
STAGING_BATCH_ID="<safe-staging-batch-id>" \
RLS_VALIDATION_SAMPLES=5 \
node scripts/collect-rls-staging-validation-evidence.mjs
```

4. Store only the generated safe summary. Do not store raw bodies, IDs, tokens, cookies, or redirect locations.

## Rollback And Cost Control

If validation fails:

1. Set any enabled staging RLS route flag back to false.
2. Redeploy or restart the staging backend task if needed.
3. Verify route behavior returns to flag-off baseline.
4. Scale staging ECS service down to `0` if cost matters and validation is paused.
5. Stop disposable staging DB/Redis only after evidence and rollback requirements are satisfied.

## No-Go Criteria

- Endpoint resolves under `mscqr.com` without a separate reviewed allowlist.
- Endpoint host contains `prod` or `production`.
- Staging task points at production RDS, RDS Proxy, Redis, or object storage.
- GitHub staging variables still point at `https://www.mscqr.com`.
- `/api/health` or selected health route is unhealthy.
- Collector dry-run or host guard fails.
- Any real secret value appears in repo, evidence, docs, workflow summaries, or logs.

## CTO Recommendations

1. Convert this runbook into Terraform once the endpoint is proven, because staging should be reproducible and drift-controlled.
2. Add staging-specific alarms before relying on the endpoint for release confidence: health, 5xx, target health, DB connections, Redis connectivity, and task restarts.
3. Add a short-lived seed/reset path for staging smoke users and safe test batches so RLS validation does not depend on manual database edits.
4. Make staging API-only first; add staging frontend after API isolation is proven.
