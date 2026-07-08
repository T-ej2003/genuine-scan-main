# MSCQR Staging Terraform Remote State Runbook

Date: 2026-07-08
Scope: migrate reconciled staging Terraform state from local-only ignored backup
to an S3 backend with S3 lockfile state locking.

This runbook does not authorize `terraform apply`, application resource
mutation, production database access, RLS enablement, or deletion/recreation of
staging ECS, RDS, Redis, ALB, application S3, KMS, or IAM resources.

## Why Local State Is Unsafe

Local state is a single-machine control-plane file. Losing it can force risky
imports, stale state can produce destructive plans, and local copies are easy to
misplace or accidentally expose. The reconciled staging state must be durable,
versioned, access-controlled, encrypted, and locked before routine plan/apply
operations continue.

## Backend Standard

- Bucket: `mscqr-staging-terraform-state-368992683803`
- Key: `staging-api/terraform.tfstate`
- Region: `eu-west-2`
- Encryption: `encrypt = true` with bucket SSE-S3 controls
- Locking: S3 lockfile with `use_lockfile = true`
- Account guard: `allowed_account_ids = ["368992683803"]`

DynamoDB locking is deprecated for new Terraform S3 backend usage. Do not make
DynamoDB the default locking path. Keep it only as legacy compatibility if a
future migration from older tooling explicitly requires it.

## Required IAM

Attach
`documents/ops/iam/MSCQR_STAGING_TERRAFORM_BACKEND_ACCESS_POLICY_2026-07-08.json`
to both the staging plan role and staging apply role. It grants:

- `s3:ListBucket` on `arn:aws:s3:::mscqr-staging-terraform-state-368992683803`
  limited to prefix `staging-api/terraform.tfstate*`.
- `s3:GetObject` and `s3:PutObject` on
  `arn:aws:s3:::mscqr-staging-terraform-state-368992683803/staging-api/terraform.tfstate`.
- `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject` on
  `arn:aws:s3:::mscqr-staging-terraform-state-368992683803/staging-api/terraform.tfstate.tflock`.

Use
`documents/ops/iam/MSCQR_STAGING_TERRAFORM_BACKEND_BOOTSTRAP_POLICY_2026-07-08.json`
only for the identity that creates/configures the backend bucket. Normal
plan/apply roles should not need bucket-creation permissions.

Validate templates before any IAM change:

```sh
npm run check:staging-iam-policies
npm run test:staging-terraform-backend
```

## Bootstrap Backend Bucket

Use a staging Terraform provisioning or apply role, not root and not a
production-looking profile:

```sh
set +x
AWS_PROFILE="<staging-terraform-provisioning-or-apply-profile>" \
AWS_REGION="eu-west-2" \
MSCQR_STAGING_TERRAFORM_BACKEND_BOOTSTRAP_ENABLED=true \
MSCQR_STAGING_TERRAFORM_BACKEND_BOOTSTRAP_CONFIRM=MSCQR_BOOTSTRAP_STAGING_TERRAFORM_BACKEND_ONCE \
node scripts/bootstrap-staging-terraform-backend.mjs
```

The script creates/configures only the backend bucket. It enables bucket
versioning, SSE-S3 encryption, public access block, bucket-owner-enforced
ownership controls, noncurrent version lifecycle retention, and a deny-insecure
transport bucket policy. If the bucket already exists, rerunning the script is
idempotent and reconciles the same controls.

## Migrate Reconciled State

Do not invent state. Use the explicit final reconciled 39-resource backup path:

```sh
set +x
AWS_PROFILE="<staging-terraform-provisioning-or-apply-profile>" \
AWS_REGION="eu-west-2" \
MSCQR_STAGING_TERRAFORM_STATE_MIGRATION_ENABLED=true \
MSCQR_STAGING_TERRAFORM_STATE_MIGRATION_CONFIRM=MSCQR_MIGRATE_STAGING_TERRAFORM_STATE_ONCE \
node scripts/migrate-staging-terraform-state-to-s3.mjs \
  --source-state ".terraform-plans/staging/state-backups/terraform.tfstate.final-reconciled-39-resources-2026-07-08.json"
```

The wrapper verifies exactly 39 managed resource addresses unless
`--expected-count` is deliberately supplied. It also requires these addresses:

- `aws_ecs_service.backend`
- `aws_db_instance.staging`
- `aws_elasticache_replication_group.staging`
- `aws_lb.staging`
- `aws_vpc_security_group_ingress_rule.alb_operator_http["46.208.2.24/32"]`

It refuses production-looking state values, missing state, wrong counts,
missing required addresses, wrong account, wrong region, root identities,
production-looking profiles, and missing gates. It runs `terraform init
-migrate-state -force-copy` only from a temporary Terraform working copy and
writes redacted evidence JSON under `.terraform-plans/staging/`.

Do not delete the local backup until remote state is verified.

## Verify After Migration

Reinitialize the real working tree against the S3 backend:

```sh
set +x
AWS_PROFILE="<staging-terraform-provisioning-profile>" \
AWS_REGION="eu-west-2" \
terraform -chdir=infra/terraform/staging-api init
```

Generate a fresh plan through the wrapper, not raw Terraform:

```sh
set +x
AWS_PROFILE="<staging-terraform-provisioning-profile>" \
AWS_REGION="eu-west-2" \
MSCQR_STAGING_TERRAFORM_PLAN_ENABLED=true \
MSCQR_STAGING_TERRAFORM_PLAN_CONFIRM=MSCQR_GENERATE_STAGING_PLAN_ONLY \
npm run plan:staging-terraform
```

The required post-migration result is `add=0`, `change=0`, and `destroy=0`.
Any non-zero count means stop and inspect read-only evidence before considering
another migration or plan.

## Recovery If Migration Fails

1. Do not run `terraform apply`.
2. Do not delete the ignored local state backup.
3. Inspect only the redacted migration evidence JSON under
   `.terraform-plans/staging/`.
4. Confirm the backend bucket exists, versioning is enabled, and IAM includes
   the backend access policy.
5. Confirm no lockfile is stale before retrying. If a lock exists, identify the
   failed Terraform command and operator before deleting a lockfile.
6. Retry only after the source state backup, expected count, required
   addresses, identity, region, and gates are all rechecked.

## CTO Recommendations

- Replace long-lived human AWS profiles with short-lived federation or GitHub
  OIDC once the first remote-state migration is proven.
- Add a scheduled read-only drift check that runs `terraform plan` from the
  remote backend and alerts on any non-zero add/change/destroy count.
- Add S3 server access logging or CloudTrail data events for the backend bucket
  before staging becomes shared by multiple operators.
- Move Redis to AUTH plus in-transit TLS before staging becomes long-lived.
