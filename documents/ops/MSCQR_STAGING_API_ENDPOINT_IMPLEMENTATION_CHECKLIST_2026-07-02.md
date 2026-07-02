# MSCQR Staging API Endpoint Implementation Checklist - 2026-07-02

## Scope

This is a docs-only implementation plan for a real non-production AWS staging API endpoint. It builds from:

- `documents/ops/MSCQR_STAGING_API_ENDPOINT_PLAN_2026-07-01.md`
- `documents/ops/MSCQR_STAGING_API_ENDPOINT_RUNBOOK_2026-07-01.md`
- `documents/security/mscqr_staging_endpoint_readiness_checklist.json`
- `documents/ops/MSCQR_RLS_STAGING_VALIDATION_RUNBOOK_2026-06-30.md`

No AWS resources were created. No production resource was mutated. No deployment was run. No production database was used. No secret values are recorded here.

Follow-on preparation note: `documents/ops/MSCQR_STAGING_RLS_SEED_AND_TERRAFORM_PLAN_2026-07-02.md` now captures the next implementation bridge: a guarded staging RLS validation seed and a preparation-only Terraform skeleton under `infra/terraform/staging-api/`. That follow-on work still forbids Terraform apply, AWS resource creation, production DB use, and production/global RLS enablement.

## Executive Decision

Recommended staging shape: create a separate API-only ECS staging backend in `eu-west-2`, backed by separate staging Postgres, separate staging Valkey/Redis, separate staging S3, separate staging secrets, and a dedicated staging ALB with an AWS-generated `*.elb.amazonaws.com` DNS name.

Do not reuse the production ECS service, production RDS/RDS Proxy, production Valkey group, production S3 bucket, production task secrets, production CloudFront path, production Route 53 hostname, or production listener rules as staging.

## Live Read-Only Discovery Summary

Discovery was run with AWS CLI list/describe/get calls only.

| Area | Current visible state |
| --- | --- |
| Account | `368992683803`; active CLI ARN was `arn:aws:iam::368992683803:root` |
| Region | `eu-west-2` |
| ECS cluster | `mscqr-prod-euw2-main` only |
| ECS services | `mscqr-backend-servi-euw2`, `mscqr-frontend-servi-euw2` |
| Backend task definition | `mscqr-backend:46`, Fargate, `2048` CPU, `4096` MB, x86_64 |
| Backend image tag | `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend:0637b4ab25156b922d57826e146568219f78c013` |
| Backend latest matching digest | `sha256:e0b618221fc2f177602afc3c2b4ec82f8c53d79817e8bb379add6a3ccd2e9553` |
| Production ALB | `mscqr-alb-euw2`, DNS `mscqr-alb-euw2-524835535.eu-west-2.elb.amazonaws.com` |
| Production ALB rules | `/api`, `/api/*`, `/health`, `/health/*`, and `ecs-backend-probe.mscqr.com` forward to production backend target group |
| Production backend target group | `mscqr-backend-tg-euw2-v2`, port `4000`, health `/health/live` |
| Production frontend target group | `mscqr-frontend-ecs-tg-euw2`, port `80`, health `/healthz` |
| Production RDS | `mscqr-prod-db`, Postgres `18.3`, `db.t4g.medium`, Multi-AZ, `100` GB gp3 |
| Production RDS Proxy | `mscqr-prod-db-proxy`, endpoint `mscqr-prod-db-proxy.proxy-c3ewey6o6mq5.eu-west-2.rds.amazonaws.com` |
| Production Redis | `mscqr-redis-euw2-primary`, Valkey, `cache.t4g.medium`, port `6379` |
| Production S3 | `mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an` only |
| ACM | One issued cert for `mscqr.com` only |
| Route 53 | Public hosted zone `mscqr.com.` only |
| GitHub repo | `T-ej2003/genuine-scan-main`, default branch `main` |
| GitHub staging vars | `STAGING_SMOKE_BASE_URL=https://www.mscqr.com`, `STAGING_SMOKE_API_BASE_URL=https://www.mscqr.com/api` |
| GitHub staging secrets | Names only: `STAGING_SMOKE_LOGIN_EMAIL`, `STAGING_SMOKE_LOGIN_PASSWORD` |

Security note: actual resource creation should not be done from root credentials. Use a least-privilege staging provisioning role or reviewed IaC pipeline before any apply.

## Proposed Resource Names

| Resource | Proposed exact name | Rationale |
| --- | --- | --- |
| ECS cluster | `mscqr-staging-euw2-main` | Separate from `mscqr-prod-euw2-main` |
| ECS service | `mscqr-staging-backend-service-euw2` | Backend-only staging service |
| ECS task family | `mscqr-staging-backend` | Separate task revision history from production |
| Container name | `backend` | Reuse app container contract |
| CloudWatch log group | `/ecs/mscqr-staging-backend` | 14-day retention recommended |
| Task execution role | `mscqr-staging-ecs-execution-role` | Separate secret/log pull scope |
| Task role | `mscqr-staging-ecs-task-role` | Staging-only S3/KMS/Secrets permissions |
| ALB | `mscqr-stg-alb-euw2` | Dedicated staging ingress; under ALB 32-char limit |
| ALB SG | `mscqr-stg-alb-sg-euw2` | Dedicated ingress controls |
| ECS SG | `mscqr-stg-ecs-sg-euw2` | Allow only staging ALB to backend port |
| DB SG | `mscqr-stg-db-sg-euw2` | Allow only staging ECS to Postgres |
| Redis SG | `mscqr-stg-redis-sg-euw2` | Allow only staging ECS to Valkey |
| Target group | `mscqr-stg-backend-tg-euw2` | Port `4000`, path `/health/live` |
| DB subnet group | `mscqr-staging-db-subnet-euw2` | Use private RDS subnets |
| RDS instance | `mscqr-staging-db` | Fresh staging Postgres, not snapshot by default |
| Redis subnet group | `mscqr-staging-redis-subnet-euw2` | Staging cache subnet group |
| Redis group | `mscqr-staging-redis-euw2` | Separate Valkey cache |
| S3 bucket | `mscqr-staging-euw2-artifacts-368992683803` | Separate staging bucket |
| S3 prefix | `rls-validation/` | Safe collector evidence namespace |
| Secrets prefix | `mscqr/staging/` | Parallel to production names without shared values |

## Network Plan

Use the existing VPC `vpc-09825a6dc884b486a` only as shared network fabric. Do not reuse production security groups for staging services.

Existing app private subnets suitable for ECS tasks:

- `subnet-07e0a76e3a5241138` - `mscqr-prod-euw2-app-a`, `eu-west-2a`
- `subnet-068d949017bd2ce45` - `mscqr-prod-euw2-app-b`, `eu-west-2b`

Existing private DB subnets suitable for a staging DB subnet group:

- `subnet-08c91af6e22933f3f` - `RDS-Pvt-subnet-1`, `eu-west-2a`
- `subnet-06d49071d962ab1b4` - `RDS-Pvt-subnet-2`, `eu-west-2b`
- `subnet-0bf2f384be86fd560` - `RDS-Pvt-subnet-3`, `eu-west-2c`

ALB choice:

- Preferred for this first validation: dedicated staging ALB `mscqr-stg-alb-euw2`.
- Listener: HTTP `80` forwarding directly to `mscqr-stg-backend-tg-euw2`.
- Base URL after creation: `http://<created-staging-alb-dns>`.
- Do not create a `*.mscqr.com` staging hostname in this phase because the collector intentionally rejects `mscqr.com` and `*.mscqr.com`.
- Do not modify production ALB rules for this first staging endpoint.

Security group model:

- `mscqr-stg-alb-sg-euw2`: temporary inbound `80/tcp` only from approved operator/test CIDRs.
- `mscqr-stg-ecs-sg-euw2`: inbound `4000/tcp` only from `mscqr-stg-alb-sg-euw2`; egress required for RDS, Redis, S3, Secrets Manager, CloudWatch, ECR, and SMTP if enabled.
- `mscqr-stg-db-sg-euw2`: inbound `5432/tcp` only from `mscqr-stg-ecs-sg-euw2`.
- `mscqr-stg-redis-sg-euw2`: inbound `6379/tcp` only from `mscqr-stg-ecs-sg-euw2`.

If GitHub-hosted `ubuntu-latest` must run staging smoke, the ALB must be reachable from GitHub-hosted runner IPs or the workflow must move to a controlled self-hosted runner. Do not silently open a broad staging API unless that exposure is explicitly approved.

## Staging Database Choice

Recommended: fresh isolated RDS Postgres `mscqr-staging-db`.

Configuration:

- Engine: PostgreSQL, same major family as production where available.
- Instance class: `db.t4g.small` for cost-controlled validation.
- Deployment: Single-AZ for first staging API validation.
- Storage: gp3, start at `30` GB unless realistic RLS data requires more.
- Public accessibility: `false`.
- Security group: `mscqr-stg-db-sg-euw2`.
- Subnet group: `mscqr-staging-db-subnet-euw2`.
- Credentials: staging-only generated credentials in Secrets Manager.

Do not restore production snapshots by default. Read-only discovery found encrypted automated production snapshots, including `rds:mscqr-prod-db-2026-07-01-04-34`, but snapshot restore is a separate data-handling project because it must include sanitization proof before staging can use it.

Required migration command after the staging DB exists:

```sh
set +x
DATABASE_URL="$STAGING_DATABASE_URL" \
npx prisma migrate deploy --schema backend/prisma/schema.prisma
```

## Staging Redis Choice

Recommended: separate ElastiCache Valkey replication group `mscqr-staging-redis-euw2`.

Configuration:

- Engine: Valkey.
- Node type: `cache.t4g.micro` for first validation.
- Replica count: `0` for low-cost staging.
- Automatic failover: disabled for first validation.
- Security group: `mscqr-stg-redis-sg-euw2`.
- Subnet group: `mscqr-staging-redis-subnet-euw2`.

Do not use production `mscqr-redis-euw2-primary` for staging, even with a logical DB number or key prefix. The current production Redis security group allows production ECS self-reference on `6379`; staging needs its own trust boundary.

## Staging S3/Object Storage Choice

Recommended: separate bucket `mscqr-staging-euw2-artifacts-368992683803`.

Required controls:

- Block all public access.
- Bucket owner enforced object ownership.
- Server-side encryption enabled.
- Versioning enabled for evidence artifacts.
- Lifecycle expiration for `rls-validation/` after an approved retention window.
- Task role scoped to this bucket and prefix only.

Do not write staging evidence to `mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an`.

## Staging Secrets

Create staging-only secret names under `mscqr/staging/`. Use generated values only; do not copy production values.

Required names:

- `mscqr/staging/database`
- `mscqr/staging/redis`
- `mscqr/staging/jwt`
- `mscqr/staging/qr_sign_private_key`
- `mscqr/staging/qr_sign_public_key`
- `mscqr/staging/ip-hash-salt-current`
- `mscqr/staging/token-hash-secret-current`
- `mscqr/staging/scan-fingerprint-secret`
- `mscqr/staging/printer-sse-sign-secret-current`
- `mscqr/staging/customer-verify-otp-secret`
- `mscqr/staging/customer-verify-token-secret`
- `mscqr/staging/incident-hash-salt-current`
- `mscqr/staging/auth-mfa-encryption-key`
- `mscqr/staging/smtp-pass` if email smoke is enabled

Task definition secret references must not contain `mscqr/prod/`.

## Staging ECS Task Definition

Base the first staging task definition on production `mscqr-backend:46`, but replace every production secret and production URL.

Recommended first staging task size:

- CPU: `1024`
- Memory: `2048`
- Desired count: `1`

Required environment values:

- `NODE_ENV=production` only if production startup hardening is required; otherwise use `NODE_ENV=staging` if the app path supports it.
- `SENTRY_ENVIRONMENT=staging`
- `RUN_DB_MIGRATIONS_ON_START=false`
- `RUN_BACKGROUND_WORKERS=false` for API-only RLS validation unless a route requires workers.
- `OBJECT_STORAGE_REGION=eu-west-2`
- `OBJECT_STORAGE_BUCKET=mscqr-staging-euw2-artifacts-368992683803`
- `PUBLIC_APP_URL=http://<created-staging-alb-dns>`
- `WEB_APP_BASE_URL=http://<created-staging-alb-dns>`
- `APP_URL=http://<created-staging-alb-dns>`
- `FRONTEND_URL=http://<created-staging-alb-dns>`
- `PUBLIC_ADMIN_WEB_BASE_URL=http://<created-staging-alb-dns>`
- `PUBLIC_VERIFY_WEB_BASE_URL=http://<created-staging-alb-dns>`
- `PUBLIC_SCAN_WEB_BASE_URL=http://<created-staging-alb-dns>`
- `CORS_ORIGIN=http://<created-staging-alb-dns>`
- `WEBAUTHN_ORIGIN=http://<created-staging-alb-dns>` only if browser smoke is intentionally enabled over this temporary endpoint.
- `WEBAUTHN_RP_ID=<created-staging-alb-dns>` only if browser smoke is intentionally enabled; otherwise do not exercise WebAuthn.

RLS flags must start false:

- `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED=false`
- `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED=false`
- `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED=false`

## Target Group And ALB Route

Create target group:

- Name: `mscqr-stg-backend-tg-euw2`
- Type: `ip`
- Protocol: `HTTP`
- Port: `4000`
- VPC: `vpc-09825a6dc884b486a`
- Health check: `HTTP /health/live`
- Matcher: `200-399`

Create ALB:

- Name: `mscqr-stg-alb-euw2`
- Scheme: `internet-facing` for operator/GitHub reachability, or `internal` if validation runs inside the VPC.
- Subnets: use public ALB subnets after confirming route-table internet ingress. Existing names are `mscqr-prod-euw2-public=a` and `mscqr-prod-euw2-public=b`.
- Security group: `mscqr-stg-alb-sg-euw2`.

Create listener:

- Port `80`
- Protocol `HTTP`
- Default action forwards to `mscqr-stg-backend-tg-euw2`.

Do not create a production ALB listener rule for staging in this phase. The existing production HTTPS listener already routes `/api` and `/health` to production.

## GitHub Staging Variable Update Plan

Current GitHub staging variables are unsafe:

- `STAGING_SMOKE_BASE_URL=https://www.mscqr.com`
- `STAGING_SMOKE_API_BASE_URL=https://www.mscqr.com/api`

Split the update into two stages. The API-only HTTP ALB is acceptable for the RLS collector and backend health checks, but it is not a full release-candidate browser/auth smoke target. The existing release smoke runs on GitHub-hosted `ubuntu-latest` and can exercise login/cookie behavior; do not point it at a temporary HTTP-only API endpoint unless the task definition and smoke flow have been explicitly reviewed for non-secure staging cookies.

### API-Only RLS Collector Variables

After the staging ALB is live and health-checked, add or update only the staging collector and resource metadata variables:

```sh
gh variable set STAGING_BASE_URL --env staging --body "http://<created-staging-alb-dns>"
gh variable set AWS_REGION --env staging --body "eu-west-2"
gh variable set STAGING_ECS_CLUSTER --env staging --body "mscqr-staging-euw2-main"
gh variable set STAGING_ECS_SERVICE --env staging --body "mscqr-staging-backend-service-euw2"
gh variable set STAGING_TASK_DEFINITION --env staging --body "mscqr-staging-backend"
gh variable set STAGING_DATABASE_HOST --env staging --body "mscqr-staging-db.<generated>.eu-west-2.rds.amazonaws.com"
gh variable set STAGING_REDIS_HOST --env staging --body "mscqr-staging-redis-euw2.<generated>.euw2.cache.amazonaws.com"
gh variable set STAGING_OBJECT_STORAGE_BUCKET --env staging --body "mscqr-staging-euw2-artifacts-368992683803"
gh variable set STAGING_OBJECT_STORAGE_PREFIX --env staging --body "rls-validation/"
```

Remove or replace the existing production-facing release-smoke values before relying on the `staging` environment as evidence. If no HTTPS staging smoke target exists yet, delete the unsafe values and accept that `rc-staging-smoke` is not ready rather than letting it hit production:

```sh
gh variable delete STAGING_SMOKE_BASE_URL --env staging
gh variable delete STAGING_SMOKE_API_BASE_URL --env staging
```

### Release-Candidate Smoke Variables

Set release-smoke variables only after a reviewed staging frontend/base URL exists with HTTPS, a matching certificate, and confirmed cookie/WebAuthn behavior:

```sh
gh variable set STAGING_SMOKE_BASE_URL --env staging --body "https://<reviewed-staging-frontend-or-base-host>"
gh variable set STAGING_SMOKE_API_BASE_URL --env staging --body "https://<reviewed-staging-frontend-or-base-host>/api"
```

Required staging secret names in GitHub:

```sh
gh secret set STAGING_SMOKE_LOGIN_EMAIL --env staging
gh secret set STAGING_SMOKE_LOGIN_PASSWORD --env staging
gh secret set STAGING_AUTH_TOKEN --env staging
```

Do not paste secret values into commands stored in shell history. Use interactive `gh secret set` or stdin from an approved local secret manager.

## Smoke User And Test Data Setup

Existing runtime-safe script:

- `backend/scripts/seed-launch-smoke-users.js`
- package script: `npm run seed:launch-smoke-users`

This creates:

- `MSCQR Launch Smoke Platform`
- `MSCQR Launch Smoke Licensee`
- `MSCQR Launch Smoke Manufacturer`

Run only inside the staging backend task after the staging DB is migrated:

The staging Terraform service enables ECS Exec for this controlled migration and seed path only. The backend task role has the minimum SSM Messages channel permissions required by ECS Exec; operators still need explicit `ecs:ExecuteCommand` permission in their own IAM identity. Review command activity in CloudTrail and the staging backend CloudWatch log group after each run.

```sh
set +x
aws ecs execute-command \
  --region eu-west-2 \
  --cluster mscqr-staging-euw2-main \
  --task "<staging-backend-task-arn>" \
  --container backend \
  --interactive \
  --command "/bin/sh -lc 'NODE_ENV=staging LAUNCH_SMOKE_SEED_ENABLED=true LAUNCH_SMOKE_CONFIRM=MSCQR_CREATE_LAUNCH_SMOKE_USERS LAUNCH_SMOKE_REFRESH_ADMIN_MFA=true LAUNCH_SMOKE_MFA_CONFIRM=MSCQR_REFRESH_LAUNCH_SMOKE_ADMIN_MFA LAUNCH_SMOKE_LICENSEE_PREFIX=LSMK LAUNCH_SMOKE_SUPERADMIN_EMAIL=\"$LAUNCH_SMOKE_SUPERADMIN_EMAIL\" LAUNCH_SMOKE_LICENSEE_ADMIN_EMAIL=\"$LAUNCH_SMOKE_LICENSEE_ADMIN_EMAIL\" LAUNCH_SMOKE_MANUFACTURER_EMAIL=\"$LAUNCH_SMOKE_MANUFACTURER_EMAIL\" npm run seed:launch-smoke-users'"
```

RLS validation also needs a safe `STAGING_BATCH_ID` for `GET /api/qr/batches/:id/allocation-map`. Existing launch-smoke seeding does not create that batch. Required dependency before first collector run:

- Add or approve a staging-only synthetic RLS data seed that creates one licensee-owned batch, a small QR range, and a manufacturer link owned by the launch-smoke tenant.
- The seed must be idempotent, refuse production identifiers, print only redacted evidence, and output a single `stagingBatchId` for `STAGING_BATCH_ID`.
- Until that exists, do not run the allocation-map collector as a release-quality proof.

Proposed future package script:

```json
"seed:staging-rls-validation-data": "node scripts/seed-staging-rls-validation-data.js"
```

Proposed future staging command:

Use the same controlled ECS Exec path for this seed command only after the staging task definition, task role, and operator IAM permissions have been reviewed.

```sh
set +x
aws ecs execute-command \
  --region eu-west-2 \
  --cluster mscqr-staging-euw2-main \
  --task "<staging-backend-task-arn>" \
  --container backend \
  --interactive \
  --command "/bin/sh -lc 'NODE_ENV=staging STAGING_RLS_SEED_ENABLED=true STAGING_RLS_SEED_CONFIRM=MSCQR_CREATE_STAGING_RLS_VALIDATION_DATA npm run seed:staging-rls-validation-data'"
```

## Read-Only Discovery Commands

These commands are safe to rerun for plan refresh:

```sh
aws sts get-caller-identity --output json
aws ecs list-clusters --region eu-west-2 --output json
aws ecs list-services --region eu-west-2 --cluster mscqr-prod-euw2-main --output json
aws ecs describe-services --region eu-west-2 --cluster mscqr-prod-euw2-main --services mscqr-backend-servi-euw2 mscqr-frontend-servi-euw2 --output json
aws ecs describe-task-definition --region eu-west-2 --task-definition mscqr-backend:46 --output json
aws elbv2 describe-load-balancers --region eu-west-2 --output json
aws elbv2 describe-target-groups --region eu-west-2 --output json
aws elbv2 describe-listeners --region eu-west-2 --load-balancer-arn arn:aws:elasticloadbalancing:eu-west-2:368992683803:loadbalancer/app/mscqr-alb-euw2/cda0292be6e39608 --output json
aws elbv2 describe-rules --region eu-west-2 --listener-arn arn:aws:elasticloadbalancing:eu-west-2:368992683803:listener/app/mscqr-alb-euw2/cda0292be6e39608/909cba320a6bbbf6 --output json
aws ec2 describe-subnets --region eu-west-2 --filters Name=vpc-id,Values=vpc-09825a6dc884b486a --output json
aws ec2 describe-security-groups --region eu-west-2 --filters Name=vpc-id,Values=vpc-09825a6dc884b486a --output json
aws rds describe-db-instances --region eu-west-2 --output json
aws rds describe-db-proxies --region eu-west-2 --output json
aws rds describe-db-subnet-groups --region eu-west-2 --output json
aws elasticache describe-replication-groups --region eu-west-2 --output json
aws elasticache describe-cache-subnet-groups --region eu-west-2 --output json
aws s3api list-buckets --query 'Buckets[].Name' --output json
aws secretsmanager list-secrets --region eu-west-2 --filters Key=name,Values=mscqr --output json
aws ecr describe-repositories --region eu-west-2 --output json
aws ecr describe-images --region eu-west-2 --repository-name mscqr-backend --output json
aws acm list-certificates --region eu-west-2 --output json
aws route53 list-hosted-zones --output json
gh variable list --env staging
gh secret list --env staging
```

## Dry-Run Command Plan

Commands in this section either use AWS dry-run support, generate request skeletons, or print local payloads. They are not resource creation commands.

### 1. Repo Guards

```sh
node scripts/check-staging-endpoint-readiness.mjs --dry-run
node scripts/check-staging-endpoint-readiness.mjs --self-check-redaction
node scripts/collect-rls-staging-validation-evidence.mjs --self-check-host-guard
```

### 2. Security Group Dry Runs

```sh
aws ec2 create-security-group --dry-run --region eu-west-2 --vpc-id vpc-09825a6dc884b486a --group-name mscqr-stg-alb-sg-euw2 --description "MSCQR staging ALB HTTP ingress"
aws ec2 create-security-group --dry-run --region eu-west-2 --vpc-id vpc-09825a6dc884b486a --group-name mscqr-stg-ecs-sg-euw2 --description "MSCQR staging ECS backend"
aws ec2 create-security-group --dry-run --region eu-west-2 --vpc-id vpc-09825a6dc884b486a --group-name mscqr-stg-db-sg-euw2 --description "MSCQR staging Postgres"
aws ec2 create-security-group --dry-run --region eu-west-2 --vpc-id vpc-09825a6dc884b486a --group-name mscqr-stg-redis-sg-euw2 --description "MSCQR staging Valkey"
```

Expected dry-run result with authorized credentials: `DryRunOperation`.

### 3. Non-Dry-Run Resource Skeletons

These generate client-side input templates only:

```sh
aws elbv2 create-target-group --generate-cli-skeleton input
aws elbv2 create-load-balancer --generate-cli-skeleton input
aws elbv2 create-listener --generate-cli-skeleton input
aws rds create-db-subnet-group --generate-cli-skeleton input
aws rds create-db-instance --generate-cli-skeleton input
aws elasticache create-cache-subnet-group --generate-cli-skeleton input
aws elasticache create-replication-group --generate-cli-skeleton input
aws s3api create-bucket --generate-cli-skeleton input
aws ecs create-cluster --generate-cli-skeleton input
aws ecs register-task-definition --generate-cli-skeleton input
aws ecs create-service --generate-cli-skeleton input
```

### 4. Staging Task Payload Dry Run

After `mscqr-staging-backend` exists, use the repo deploy helper in dry-run mode for image-only updates:

```sh
DRY_RUN=true \
AWS_REGION=eu-west-2 \
CLUSTER_NAME=mscqr-staging-euw2-main \
SERVICE_NAME=mscqr-staging-backend-service-euw2 \
TASK_DEFINITION=mscqr-staging-backend \
CONTAINER_NAME=backend \
IMAGE_URI="368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:e0b618221fc2f177602afc3c2b4ec82f8c53d79817e8bb379add6a3ccd2e9553" \
EXPECTED_GIT_SHA="0637b4ab25156b922d57826e146568219f78c013" \
./scripts/aws/deploy-ecs-service.sh
```

### 5. Post-Create Read-Only Verification Commands

Run only after resources are intentionally created through reviewed apply:

```sh
aws ecs describe-services --region eu-west-2 --cluster mscqr-staging-euw2-main --services mscqr-staging-backend-service-euw2 --output json
aws ecs describe-task-definition --region eu-west-2 --task-definition mscqr-staging-backend --output json
aws elbv2 describe-target-health --region eu-west-2 --target-group-arn "<staging-target-group-arn>" --output json
curl -fsS "http://<created-staging-alb-dns>/health/live"
curl -fsS "http://<created-staging-alb-dns>/api/health"
```

### 6. Collector Baseline Commands

Run only after staging auth token and staging batch ID are created:

```sh
STAGING_BASE_URL="http://<created-staging-alb-dns>" \
node scripts/collect-rls-staging-validation-evidence.mjs --dry-run
```

```sh
set +x
STAGING_BASE_URL="http://<created-staging-alb-dns>" \
STAGING_AUTH_TOKEN="$STAGING_AUTH_TOKEN" \
STAGING_BATCH_ID="$STAGING_BATCH_ID" \
RLS_VALIDATION_SAMPLES=5 \
node scripts/collect-rls-staging-validation-evidence.mjs
```

## Implementation Checklist

### Phase 0 - Approval And Identity

- [ ] Confirm this remains a staging-only project.
- [ ] Stop using root credentials for future applies.
- [ ] Create or select a least-privilege staging provisioning role.
- [ ] Confirm no production database, production Redis, or production bucket will be referenced by staging task definitions.
- [ ] Confirm `node scripts/collect-rls-staging-validation-evidence.mjs --self-check-host-guard` passes.

### Phase 1 - Staging Infrastructure Review

- [ ] Review proposed names.
- [ ] Review VPC/subnet/security group plan.
- [ ] Decide whether staging ALB is public allowlisted, internal, or public broad access.
- [ ] If GitHub-hosted staging smoke must run, decide runner reachability before updating GitHub vars.
- [ ] Prepare reviewed IaC or reviewed AWS CLI apply scripts.

### Phase 2 - Data Plane

- [ ] Create `mscqr-stg-db-sg-euw2`.
- [ ] Create `mscqr-staging-db-subnet-euw2`.
- [ ] Create `mscqr-staging-db`.
- [ ] Create `mscqr-stg-redis-sg-euw2`.
- [ ] Create `mscqr-staging-redis-subnet-euw2`.
- [ ] Create `mscqr-staging-redis-euw2`.
- [ ] Create `mscqr-staging-euw2-artifacts-368992683803`.
- [ ] Enable S3 block-public-access, encryption, versioning, lifecycle rules, and narrow IAM.

### Phase 3 - Secrets And IAM

- [ ] Create `mscqr-staging-ecs-execution-role`.
- [ ] Create `mscqr-staging-ecs-task-role`.
- [ ] Create all `mscqr/staging/*` secrets with generated staging values.
- [ ] Confirm no task secret ARN contains `mscqr/prod/`.
- [ ] Confirm task role has no production S3 bucket access.

### Phase 4 - ECS And ALB

- [ ] Create `mscqr-staging-euw2-main`.
- [ ] Create `/ecs/mscqr-staging-backend` with 14-day retention.
- [ ] Register `mscqr-staging-backend`.
- [ ] Create `mscqr-stg-backend-tg-euw2`.
- [ ] Create `mscqr-stg-alb-euw2`.
- [ ] Create HTTP listener forwarding to staging target group.
- [ ] Create `mscqr-staging-backend-service-euw2`, desired count `1`.
- [ ] Verify target health and `/health/live`.

### Phase 5 - Migrations And Seed

- [ ] Run Prisma migrations against staging `DATABASE_URL` only.
- [ ] Run launch-smoke user seed against staging task only.
- [ ] Add or approve staging RLS validation data seed for `STAGING_BATCH_ID`.
- [ ] Store smoke credentials in GitHub staging secrets.
- [ ] Store collector token only in secure operator/GitHub secret context.

### Phase 6 - GitHub Staging Config

- [ ] Replace production-facing `STAGING_SMOKE_BASE_URL`.
- [ ] Replace production-facing `STAGING_SMOKE_API_BASE_URL`.
- [ ] Add `STAGING_BASE_URL`.
- [ ] Add staging ECS/DB/Redis/S3 vars.
- [ ] Run `node scripts/check-staging-endpoint-readiness.mjs --dry-run` with the proposed env values.
- [ ] Run `npm run verify:staging-smoke` only when an HTTPS staging smoke target is reachable from the workflow runner and auth/cookie behavior is confirmed.

### Phase 7 - RLS Baseline

- [ ] Confirm all staging RLS flags are false.
- [ ] Run collector dry-run.
- [ ] Run baseline collector with safe staging token and batch ID.
- [ ] Attach only safe summary evidence; no raw bodies, IDs, cookies, redirect locations, or tokens.

## Cost Estimate

Pricing inputs were gathered with read-only AWS Pricing and Cost Explorer where available. Actual monthly cost depends on traffic, storage, log volume, task uptime, and NAT/data processing.

| Item | Sizing assumption | Source/assumption | Estimated monthly USD |
| --- | --- | --- | ---: |
| ECS Fargate backend | 1 task, `1024` CPU, `2048` MB, always on | Current account ECS cost category was about `$102.26` in June for the visible production ECS footprint; staging is sized down | `$25-$45` |
| Dedicated staging ALB | 1 ALB, low LCU | Pricing API returned `$0.02646` per ALB-hour in London, before LCU | `$20-$25` |
| Staging RDS | `db.t4g.small`, Single-AZ, 730 hours | Pricing API returned `$0.036` per hour | `$26.28` compute plus storage |
| RDS gp3 storage | 30 GB | Estimate; verify storage pricing before apply | `$3-$5` |
| Staging Valkey | 1 `cache.t4g.micro`, 730 hours | Pricing API returned `$0.0144` per hour | `$10.51` |
| S3 staging bucket | Low evidence volume | Current account S3 was under `$0.10` in June | `<$1` |
| Secrets Manager | About 16 staging secrets | Current account Secrets Manager was about `$7.17` in June for comparable prod secret count | `$6-$8` |
| CloudWatch Logs | 14-day retention, low traffic | Estimate from current account category | `$1-$5` |
| Data transfer/NAT | Low smoke/RLS traffic | Shared VPC costs may rise with NAT/data processing | `$0-$5` incremental |

Expected total for always-on API-only staging with dedicated ALB: about `$90-$120/month`.

Cost controls:

- Scale ECS desired count to `0` when validation is paused.
- Stop the RDS instance outside validation windows if acceptable.
- Keep log retention at `14` days initially.
- Keep S3 lifecycle expiration on `rls-validation/`.
- Do not use Multi-AZ RDS until staging becomes a permanent release gate.

## CTO Recommendations

1. Convert this plan to Terraform before the first apply. CLI-only creation will drift quickly and is hard to review.
2. Create a staging OIDC role for GitHub instead of access keys or root. Staging should have its own permission boundary.
3. Add a small runtime health dashboard for staging: API health, DB connectivity, Redis connectivity, S3 write/read, release SHA, target health, and RLS flag states.
4. Add the missing idempotent staging RLS seed script before calling the allocation-map collector release-quality evidence.
5. Move `rc-staging-smoke` to a controlled self-hosted runner or explicitly document public staging exposure. A locked-down ALB and GitHub-hosted dynamic IPs do not work cleanly together.
6. Add AWS Budget alerts for staging at `$50`, `$100`, and `$150` monthly thresholds before resources are created.
7. Keep staging synthetic. Do not use production snapshots until a sanitization process and evidence template exist.
