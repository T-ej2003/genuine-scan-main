# MSCQR Staging RLS Seed And Terraform Plan - 2026-07-02

## Scope

This preparation adds a staging-only RLS validation data seed and a Terraform skeleton for the proposed staging API endpoint.

It does not run Terraform apply, create AWS resources, deploy services, use the production database, enable production RLS, enable global/table RLS, wire runtime routes, or remove app-layer authorization.

## Why The Seed Is Required

The RLS evidence collector needs a safe `STAGING_BATCH_ID` for:

- `GET /api/qr/batches/:id/allocation-map`

The existing launch-smoke seed creates smoke users and tenants, but it does not create a stable synthetic batch, QR range, QR code set, and manufacturer/licensee linkage for RLS validation. The new seed fills only that gap with a tiny synthetic dataset named `MSCQR Staging RLS Validation ...`.

## Seed Command

Run only against a reviewed staging or disposable local/P2 database:

```sh
cd backend
STAGING_RLS_SEED_ENABLED=true \
STAGING_RLS_SEED_CONFIRM=MSCQR_CREATE_STAGING_RLS_VALIDATION_DATA \
STAGING_RLS_SEED_ENVIRONMENT=staging \
DATABASE_URL="$STAGING_DATABASE_URL" \
npm run seed:staging-rls-validation-data
```

If a staging ECS/runtime path requires `NODE_ENV=production`, the script still refuses by default. The explicit override is:

```sh
STAGING_RLS_SEED_ALLOW_PRODUCTION_NODE_ENV_FOR_STAGING=true
STAGING_RLS_SEED_ENVIRONMENT=staging
```

The override is accepted only if `DATABASE_URL` is still non-production-looking.

## Safety Gates

The seed refuses to run unless all required gates pass:

- `STAGING_RLS_SEED_ENABLED=true`
- `STAGING_RLS_SEED_CONFIRM=MSCQR_CREATE_STAGING_RLS_VALIDATION_DATA`
- `DATABASE_URL` exists and parses as PostgreSQL
- `DATABASE_URL` does not contain `mscqr-prod`, `mscqr-prod-db-proxy`, `production`, or `prod`
- local hosts are limited to `localhost`, `127.0.0.1`, `::1`, `postgres`, and `*.local`
- every non-local `DATABASE_URL` must clearly contain `staging`, `stg`, `test`, `p2`, `tmp`, `temporary`, or `local` in the host, database name, or username
- exact reviewed non-local DB hosts can be listed in `STAGING_RLS_SEED_ALLOWED_DB_HOSTS`, but production-looking URLs are still refused even if allowlisted
- AWS RDS URLs must clearly name `staging` or `stg`, or be exact reviewed allowlist entries
- `NODE_ENV=production` is refused unless the explicit staging override is present and safe

The script does not call external APIs, does not create auth tokens, does not print `DATABASE_URL`, does not print QR codes, and does not enable RLS.

## Expected Safe Output

The script prints JSON with this shape:

```json
{
  "ok": true,
  "status": "ready",
  "created": {
    "organization": true,
    "licensee": true,
    "licenseeAdmin": true,
    "manufacturer": true,
    "manufacturerLicenseeLink": true,
    "qrRange": true,
    "batch": true,
    "qrCodes": 5,
    "printers": 0
  },
  "reused": {
    "organization": false,
    "licensee": false,
    "licenseeAdmin": false,
    "manufacturer": false,
    "manufacturerLicenseeLink": false,
    "qrRange": false,
    "batch": false,
    "qrCodes": 0,
    "printers": 0
  },
  "counts": {
    "batches": 1,
    "qrCodes": 5,
    "printersCreated": 0,
    "externalApiCalls": 0
  },
  "stagingBatchId": "00000000-0000-4302-8300-000000000001",
  "collectorEnvExample": {
    "STAGING_BASE_URL": "<staging-base-url>",
    "STAGING_AUTH_TOKEN": "<redacted-bearer-token>",
    "STAGING_BATCH_ID": "00000000-0000-4302-8300-000000000001",
    "RLS_VALIDATION_SAMPLES": "1"
  }
}
```

`stagingBatchId` is operator-only. It is printed because the collector requires it, but operators should not paste it into committed evidence unless the evidence format explicitly allows it.

## Collector Use

After the staging endpoint exists, the staging DB is migrated, the seed has run, and a staging-only bearer token exists in a secure operator context:

```sh
STAGING_BASE_URL="http://<staging-alb-dns>" \
STAGING_AUTH_TOKEN="<redacted-bearer-token>" \
STAGING_BATCH_ID="<operator-only-stagingBatchId-from-seed-output>" \
RLS_VALIDATION_SAMPLES=1 \
node scripts/collect-rls-staging-validation-evidence.mjs
```

Keep the collector route scope unchanged:

- `GET /api/qr/batches`
- `GET /api/qr/batches/:id/allocation-map`
- `GET /api/manufacturer/printers`

## Terraform Directory

The staging API skeleton lives in:

```sh
infra/terraform/staging-api/
```

It models the proposed staging resources from the staging endpoint plan:

- ECS cluster `mscqr-staging-euw2-main`
- ECS service `mscqr-staging-backend-service-euw2`
- ECS task family `mscqr-staging-backend`
- ALB `mscqr-stg-alb-euw2`
- target group `mscqr-stg-backend-tg-euw2`
- log group `/ecs/mscqr-staging-backend`
- RDS instance `mscqr-staging-db`
- Redis/Valkey group `mscqr-staging-redis-euw2`
- S3 bucket `mscqr-staging-euw2-artifacts-368992683803`
- IAM roles and staging-only security groups
- runtime secret references under `mscqr/staging/*`

GitHub staging variables remain documented, not managed by Terraform.

## Terraform Review Commands

Preparation-only commands:

```sh
cd infra/terraform/staging-api
terraform init
terraform fmt -check
terraform validate
terraform plan -var-file=terraform.tfvars
```

Do not run `terraform apply` without explicit approval and a reviewed uncommitted `terraform.tfvars`.

The provider pins `allowed_account_ids = [var.account_id]`, so wrong active AWS credentials should fail provider initialization or plan. Account `368992683803` is valid for this staging plan only when using a least-privilege staging provisioning role. Root credentials must not be used for apply.

`allowed_operator_cidrs` must be narrow operator or CI CIDRs. `0.0.0.0/0`, `::/0`, invalid CIDRs, and broad IPv4 masks `/0` through `/23` are rejected by Terraform variable validation.

## No Apply Policy

This PR is a bridge from RLS prototype work to Terraform-managed staging. It is not an infrastructure rollout.

Forbidden in this phase:

- `terraform apply`
- AWS resource creation
- production DB or RDS Proxy references
- production Redis references
- production S3 bucket references
- production ECS service/task mutation
- committed secrets or real secret values
- global/table RLS enablement

## Approval Checklist Before Any Future Apply

- AWS identity is a least-privilege staging provisioning role, not root.
- provider account pinning matches the reviewed staging account.
- `terraform plan` contains only `staging`/`stg` resource names.
- `terraform.tfvars` is uncommitted and contains no secret values.
- all `staging_secret_arns` point under `mscqr/staging/*`.
- `backend_image_uri` is immutable and reviewed.
- operator CIDRs are narrow and time-bound.
- RDS, Redis, S3, IAM, and ALB costs are accepted.
- rollback/removal plan is approved.
- Prisma migrations are approved for the staging DB only.
- RLS route flags start false and are enabled one at a time only after baseline evidence.

## Rollback And Removal Strategy

For the seed data, rerunning the script is idempotent and reuses the same synthetic records. If staging data must be removed, delete only records with the deterministic `MSCQR Staging RLS Validation` labels and `metadata.purpose=staging_rls_validation_seed` after confirming no collector run is in progress.

For Terraform-created staging resources, removal should be a separate reviewed change. Preserve final RDS snapshots unless the CTO/security owner explicitly approves deletion. Keep S3 evidence lifecycle rules and CloudWatch retention enabled so staging artifacts age out predictably.

## Cost Controls

- ECS desired count defaults to `1`.
- RDS defaults to `db.t4g.small`, single-AZ, 30 GiB gp3.
- Redis/Valkey defaults to `cache.t4g.micro`, one node, no automatic failover.
- CloudWatch retention defaults to 14 days.
- S3 `rls-validation/` lifecycle expiration is 30 days.
- Staging ALB ingress is limited by narrow `allowed_operator_cidrs`; broad public ingress is rejected.

## Known Gaps

- Terraform is still a skeleton until reviewed tfvars and backend state handling are chosen.
- No AWS resources exist from this PR.
- The seed does not mint or print auth tokens; the collector token must come from a secure staging auth/operator process.
- The seed does not create printer rows because `GET /api/manufacturer/printers` can validate an empty scoped list without printer dispatch side effects.
- `terraform apply` remains blocked until cost, identity, networking, and rollback approvals are complete.

## CTO Recommendations

1. Add a staging health dashboard next: deployed SHA, DB connectivity, Redis connectivity, object-storage write/read, RLS flag state, and last collector evidence timestamp.
2. Add a short-lived staging access model: narrow ALB CIDRs by default, then graduate to VPN or a self-hosted runner instead of broad public ingress.
3. Add a staging teardown/scale-down runbook with explicit data-retention exceptions for RLS evidence.
4. Add a separate secret-rotation drill for `mscqr/staging/*` before promoting this staging model to permanent pre-production.
