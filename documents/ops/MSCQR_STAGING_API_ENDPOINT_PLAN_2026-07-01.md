# MSCQR Staging API Endpoint Plan - 2026-07-01

## Purpose

Create a real non-production MSCQR staging API endpoint in AWS London (`eu-west-2`) so the RLS staging validation evidence pack can run without touching production AWS resources, production databases, production secrets, production RLS, or any `mscqr.com` production-facing hostname.

This is a planning and readiness document only. It does not create AWS resources, does not deploy to production, and does not enable global or table-level RLS.

## Discovery Summary

Repo evidence shows two deployment eras:

- Older production Docker Compose and Ansible operations in `ops/deploy/deploy.yml` and `ops/deploy/deploy-standby.yml`. These explicitly verify `https://www.mscqr.com` and are not suitable for staging RLS validation.
- Current ECS/ECR release support in `.github/workflows/publish-ecs-images.yml`, `.github/workflows/deploy-ecs-release.yml`, `scripts/aws/publish-ecs-images.sh`, and `scripts/aws/deploy-ecs-service.sh`.

Current production assumptions from local repo and inventory evidence:

- AWS region: `eu-west-2`.
- Production ECS cluster: `mscqr-prod-euw2-main`.
- Production ECS services: backend and frontend services, desired/running `2/2`.
- Production ALB: `mscqr-alb-euw2`.
- Production ECR repositories: `mscqr-backend`, `mscqr-web`, and `mscqr-worker`.
- Production database: RDS PostgreSQL `mscqr-prod-db`, accessed through RDS Proxy `mscqr-prod-db-proxy`.
- Production cache: ElastiCache Valkey/Redis replication group `mscqr-redis-euw2-primary`.
- Production object storage: S3 bucket `mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an`.
- Production public traffic path: Route 53 `mscqr.com` and `www.mscqr.com` to CloudFront/WAF to London ALB to ECS frontend/backend.
- Backend runtime requires separate secrets and environment values for `DATABASE_URL`, JWT slots, QR signing, hash salts, Redis, object storage, email, CORS, public URL bases, and printer/session signing.
- Existing RLS collector requires `STAGING_BASE_URL`, `STAGING_AUTH_TOKEN`, and `STAGING_BATCH_ID`, and rejects `mscqr.com`, `*.mscqr.com`, `production`, and `prod` hosts by default.

Existing staging support:

- GitHub has a staging smoke concept through `SMOKE_BASE_URL`, `SMOKE_API_BASE_URL`, `SMOKE_LOGIN_EMAIL`, and `SMOKE_LOGIN_PASSWORD`.
- The current config check validates presence of staging smoke values but does not prove that the endpoint is isolated from production.
- The ECS deploy workflow can target arbitrary cluster/service/task definition inputs, but it does not create staging infrastructure.
- No repo-owned staging ECS cluster/service/task-definition IaC was found.
- No repo-owned staging RDS/Redis/S3 provisioning path was found.
- No safe reviewed staging endpoint value currently exists in repo evidence.

## Problem

GitHub environment `staging` currently points smoke variables at production-facing URLs:

- `STAGING_SMOKE_BASE_URL=https://www.mscqr.com`
- `STAGING_SMOKE_API_BASE_URL=https://www.mscqr.com/api`

Those values are unsafe for RLS validation. The collector is correct to refuse them because they are under `mscqr.com`.

## Required Isolation

The staging endpoint must use a separate non-production runtime surface:

- Separate ECS backend service or task definition for staging.
- Separate staging environment variables.
- Separate staging `DATABASE_URL`.
- Separate staging Redis instance or, only for short-lived validation, a strictly isolated Redis DB/namespace with no production key overlap.
- Separate object storage bucket or separate staging prefix in a non-production bucket with IAM scoped to that prefix.
- No production DB writes.
- No production secrets copied into repo.
- Staging JWT, QR signing, hash, session, SSE, and token secrets separate from production.
- Staging public URL bases must not point at `https://www.mscqr.com`.
- Staging CORS origins must include only reviewed staging frontend/base origins.
- Staged RLS route flags remain false by default and are enabled one at a time only in the staging task definition.

## Endpoint Options

### Option A: Temporary ALB DNS Endpoint

Use a dedicated staging backend ECS service behind a staging target group and expose it through an AWS ALB DNS name, for example an `*.elb.amazonaws.com` hostname.

Pros:

- Fastest safe route for RLS validation.
- Avoids `mscqr.com` and all MSCQR subdomains.
- Works with the current collector guard without weakening it.
- Good enough for API-only validation of `/api/health` and the three approved RLS routes.

Cons:

- ALB DNS names are less friendly for humans.
- TLS/certificate handling may require either a reviewed staging certificate/domain or HTTP-only internal validation if the ALB is internal and the collector runs from a trusted network.

### Option B: Dedicated Staging ALB, Listener, And Target Group

Create a dedicated staging ALB or a dedicated listener/rule and target group on non-production ingress. Keep staging ECS backend isolated from production services.

Pros:

- Cleaner long-term staging architecture.
- Stronger separation of listeners, security groups, health checks, and access logs.
- Easier to later add a staging frontend.

Cons:

- More setup than Option A.
- If implemented on an existing production ALB, it needs careful review to avoid routing mistakes and production blast radius.

### Option C: Route 53 Staging Hostname

Use a dedicated staging hostname only if explicitly allowed, for example `staging-api.<reviewed-non-prod-domain>` or a reviewed MSCQR subdomain with a narrow collector allowlist added in a separate PR.

Pros:

- Best operator ergonomics.
- Cleaner TLS and smoke-test setup.

Cons:

- Any `*.mscqr.com` staging hostname currently fails the collector by design.
- Do not relax the guard broadly. A separate reviewed PR must implement a narrow allowlist for exactly the approved staging hostname.

## Recommendation

Safest minimal path for RLS validation: create an API-only staging backend in `eu-west-2`, attach it to a staging target group, and expose it through a non-MSCQR ALB DNS name or explicitly reviewed internal hostname.

Do not use `www.mscqr.com`, `mscqr.com`, the production CloudFront distribution, the production ALB listener path, the production backend ECS service, or the production database as staging.

## AWS Implementation Path

1. Confirm the AWS account and region:
   - Account must be the intended non-production or shared account with explicit staging isolation.
   - Region must be `eu-west-2`.
2. Network:
   - Prefer an existing non-production VPC/subnet/security-group set if already reviewed.
   - If reusing production VPC networking, isolate with staging security groups, separate target group, separate ECS service, and no production data-plane access except reviewed shared infrastructure such as NAT or VPC endpoints.
3. Database:
   - Create staging RDS/Postgres or restore a sanitized snapshot.
   - Use a separate DB identifier and endpoint that does not equal `mscqr-prod-db` or `mscqr-prod-db-proxy`.
   - Run Prisma migrations against staging only:
     - `DATABASE_URL=<staging-url> npx prisma migrate deploy --schema backend/prisma/schema.prisma`
   - Do not run migrations against production DB.
4. Redis:
   - Preferred: create a separate staging ElastiCache/Redis.
   - Acceptable short-term: isolated Redis DB/index or prefix only if the Redis cluster is non-production or formally approved for isolated staging use.
   - Do not use production keys or production rate-limit/cache namespace.
5. Object storage:
   - Preferred: separate staging S3 bucket with public access blocked, versioning, encryption, and lifecycle policy.
   - Acceptable short-term: separate staging prefix in a non-production bucket with IAM scoped to that prefix.
   - Do not use the production artifact bucket/prefix for validation evidence writes.
6. Secrets:
   - Create staging-only Secrets Manager or GitHub environment secrets.
   - Required categories: database URL, JWT slots, QR signing key material, HMAC fallback if still configured, hash salts, printer SSE/session signing, SMTP if enabled, OAuth/recaptcha if flows need it.
   - Use placeholder names in repo docs only. Never commit secret values.
7. ECS:
   - Create a staging task definition from the backend production family as a starting point, then replace every production-only secret/env reference.
   - Set `NODE_ENV=production` only if startup hardening needs production parity, but keep `SENTRY_ENVIRONMENT=staging`.
   - Set RLS route flags false by default:
     - `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED=false`
     - `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED=false`
     - `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED=false`
   - Desired count can be `1` for low-cost validation.
8. Load balancer:
   - Create or reuse a staging target group for the backend container port.
   - Health check a backend health endpoint such as `/api/health`, `/health/live`, or `/health/ready` after confirming the deployed route.
   - Attach only staging ECS tasks to the staging target group.
9. Verification:
   - Verify `/api/health` or the chosen health endpoint from the staging endpoint.
   - Verify the deployed SHA through `/version` if enabled for staging.
   - Create a staging smoke user and safe staging test batch.
   - Run baseline RLS collector with all route flags off.

## GitHub Variable Update Plan

Use the GitHub `staging` environment only after the endpoint is live and verified.

Required variables:

- `STAGING_SMOKE_BASE_URL`: staging frontend/base URL if a staging frontend exists. For API-only validation, leave unset for smoke workflows that require a frontend, or point to the reviewed staging base only.
- `STAGING_SMOKE_API_BASE_URL`: real staging API URL, for example `https://<staging-alb-dns>/api`.
- `STAGING_BASE_URL`: real staging API/base URL for the RLS collector, for example `https://<staging-alb-dns>`.
- `AWS_REGION`: `eu-west-2`.
- `STAGING_ECS_CLUSTER`: staging cluster name, not `mscqr-prod-euw2-main`.
- `STAGING_ECS_SERVICE`: staging backend service name, not a production service.
- `STAGING_DATABASE_HOST`: staging DB or proxy host, not `mscqr-prod-db` or `mscqr-prod-db-proxy`.
- `STAGING_REDIS_URL` or `STAGING_REDIS_HOST`: staging Redis endpoint or isolated namespace.
- `STAGING_OBJECT_STORAGE_BUCKET` and optional `STAGING_OBJECT_STORAGE_PREFIX`: staging-only bucket/prefix.

Required secrets:

- `STAGING_DATABASE_URL`.
- `STAGING_JWT_SECRET_CURRENT` and rotation companion if used.
- `STAGING_QR_SIGN_PRIVATE_KEY`, `STAGING_QR_SIGN_PUBLIC_KEY`, and `STAGING_QR_SIGN_ACTIVE_KEY_VERSION`, or approved staging managed signing references.
- `STAGING_IP_HASH_SALT_CURRENT`, `STAGING_TOKEN_HASH_SECRET_CURRENT`, `STAGING_SCAN_FINGERPRINT_SECRET`, and other configured hash/signing salts.
- `STAGING_PRINTER_SSE_SIGN_SECRET_CURRENT`.
- `STAGING_SMOKE_AUTH_TOKEN` or operator-provided `STAGING_AUTH_TOKEN` for the collector, stored only in secure operator/GitHub secret context.
- `SMOKE_LOGIN_EMAIL` and `SMOKE_LOGIN_PASSWORD` for staging smoke users, if frontend smoke is used.

## Explicit Forbidden Shortcuts

- Do not point staging at the production database, production RDS Proxy, or production read/write credentials.
- Do not use the production ECS backend service as staging.
- Do not use `www.mscqr.com`, `mscqr.com`, or any production MSCQR domain as staging.
- Do not use production CloudFront as staging.
- Do not relax the collector guard to allow `*.mscqr.com` unless a reviewed explicit staging-hostname allowlist is created in a separate PR.
- Do not enable production RLS.
- Do not enable global or table-level RLS.
- Do not create secrets with real values in repo.
- Do not run Prisma migrations against production while building staging.

## Validation Checklist

- Endpoint is not under `mscqr.com` unless a separate reviewed explicit allowlist exists.
- Endpoint hostname does not contain `prod` or `production`.
- `/api/health` or selected backend health endpoint returns healthy.
- Deployed SHA matches expected commit if `/version` is enabled.
- Database host is not production RDS or production RDS Proxy.
- Redis endpoint/namespace is staging-isolated.
- Object storage bucket/prefix is staging-isolated.
- GitHub staging vars no longer point at production.
- `node scripts/check-staging-endpoint-readiness.mjs --dry-run` reports no production-looking values.
- `node scripts/collect-rls-staging-validation-evidence.mjs --self-check-host-guard` passes.
- RLS collector dry-run passes.
- RLS collector baseline can run with all route flags off.

## Cost Notes

- Low-cost staging can use ECS desired count `1`.
- Use the smallest acceptable RDS/Postgres class or a disposable Postgres instance if validation windows are short.
- Use small Redis/ElastiCache or isolated non-production Redis only when the isolation model is reviewed.
- Staging can be stopped or scaled down outside validation windows if cost matters.
- Keep lifecycle rules on staging evidence buckets and CloudWatch log groups so validation artifacts do not grow without bounds.

## CTO Recommendations

1. Treat this staging endpoint as the first step toward a permanent pre-production environment, not a one-off bypass for RLS.
2. Add staging IaC next: ECS service, target group/listener, Secrets Manager references, RDS, Redis, S3, alarms, and log retention should be reviewable.
3. Add a staging health dashboard covering API health, DB connectivity, Redis connectivity, object storage write/read, current deployed SHA, and RLS flag states.
4. Add least-privilege staging IAM roles now so staging does not inherit broad production task permissions.
5. Add scheduled teardown/scale-down controls for cost, but keep data snapshots/evidence retention deliberate and documented.
