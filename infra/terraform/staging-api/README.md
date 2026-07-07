# MSCQR Staging API Terraform Skeleton

This directory is a preparation-only Terraform root for the proposed staging API infrastructure. It must not be applied until the staging resource review, cost review, and security review are approved.

Hard rules:

- Do not run `terraform apply` from this PR.
- Do not point variables at production DB, Redis, S3, ECS, ALB, or Secrets Manager names.
- Do not put secret values in `terraform.tfvars` or committed files.
- Keep resource names containing `staging` or `stg`; production names are forbidden.
- The provider pins `allowed_account_ids = [var.account_id]`; wrong active AWS credentials should fail provider initialization or plan.
- Account `368992683803` may be used for staging only through a least-privilege staging provisioning role. Root credentials must not be used for apply.
- `allowed_operator_cidrs` must stay narrow. Broad public ingress such as `0.0.0.0/0`, `::/0`, and broad IPv4 masks are rejected by variable validation.
- Any planned `0.0.0.0/0` ingress, `::/0` ingress, destroy action, or production-looking resource name is an apply blocker.
- ALB ingress must remain restricted to reviewed operator CIDRs only. ALB egress must remain restricted to the staging ECS security group on backend port 4000.
- ECS egress is temporarily broad for staging-only outbound access to ECR, Secrets Manager, CloudWatch Logs, STS, package endpoints, and AWS APIs. It is not inbound exposure and should be narrowed with VPC endpoints or prefix-list controls before production reuse.
- ECS Exec is enabled on the staging backend service only for controlled staging migration and seed execution. Operators still need explicit IAM permission for `ecs:ExecuteCommand`, and command activity must be reviewed through CloudTrail plus the backend CloudWatch log group and the dedicated ECS Exec CloudWatch log group.
- ECS Exec session logging is configured at the cluster level with `logging = "OVERRIDE"` and a staging KMS-backed CloudWatch log group at `/aws/ecs/mscqr-staging/exec`.
- S3 ECS Exec session logging is intentionally not enabled in this PR. Add it later only with a dedicated staging prefix, lifecycle policy, public access block, and KMS-backed bucket encryption reviewed against the same break-glass approval checklist.

Review commands:

```sh
npm run check:staging-terraform
npm run check:staging-iam-policies
npm run check:staging-private-inputs
npm run check:staging-aws-identity
MSCQR_STAGING_TERRAFORM_PLAN_ENABLED=true MSCQR_STAGING_TERRAFORM_PLAN_CONFIRM=MSCQR_GENERATE_STAGING_PLAN_ONLY npm run plan:staging-terraform
```

Do not treat `terraform validate` as meaningful unless `terraform init -backend=false` completed successfully in the same checkout. If the AWS provider plugin schema cannot be loaded, reinstall the provider cache and rerun validation before plan review; do not rely on stale local `.terraform` state.

The repository-level clean validation guard is:

```sh
npm run check:staging-terraform
```

That guard uses a temporary `TF_DATA_DIR` and temporary `TF_PLUGIN_CACHE_DIR`, runs `init -backend=false`, `fmt -check`, `validate`, and provider schema loading, and refuses plan/apply/destroy/import arguments. GitHub Actions runs this guard in `.github/workflows/staging-infra-validation.yml` without AWS credentials.

Operator IAM policy templates are linted with:

```sh
npm run check:staging-iam-policies
```

These CI checks prove syntax and repository safety constraints only. They do not prove AWS deployability, do not replace a real `terraform plan`, and do not authorize `terraform apply`.

The first staging Terraform plan must be generated through the repository
wrapper:

```sh
MSCQR_STAGING_TERRAFORM_PLAN_ENABLED=true MSCQR_STAGING_TERRAFORM_PLAN_CONFIRM=MSCQR_GENERATE_STAGING_PLAN_ONLY npm run plan:staging-terraform
```

The wrapper calls the private input checker and AWS identity guard, refuses
unsafe identities and arguments, writes local private evidence under
`.terraform-plans/staging/`, and prints only add/change/destroy counts plus safe
metadata. Plan evidence is private and must not be committed. Cost evidence must
be created after the first real plan and before any apply approval. `terraform
apply` remains forbidden until a separate apply approval PR/checklist exists.
`npm run check:staging-private-inputs` must report zero tracked private tfvars
and zero tracked `.terraform-plans/` artifacts; force-added private inputs or
plan evidence block the workflow.

Plan review must block apply if the plan includes any `0.0.0.0/0` ingress,
`::/0` ingress, destroy action, production-looking resource name, ALB ingress
outside the reviewed operator CIDRs, DB ingress outside the ECS security group
on 5432, Redis ingress outside the ECS security group on 6379, ECS ingress
outside the ALB security group on 4000, or ALB egress outside the ECS security
group on 4000.

## Post-Apply Runtime Secret Sync

Terraform creates the staging RDS and Valkey/Redis endpoints, but it does not
write full runtime connection strings into Terraform code, plans, state, docs,
or git. After a separately approved `terraform apply`, update only these
existing runtime placeholders:

- `mscqr/staging/database-url`
- `mscqr/staging/redis-url`

The safe outputs in this module expose only non-secret endpoint metadata:

- `staging_rds_address`, `staging_rds_endpoint`, `staging_rds_port`
- `staging_rds_database_name`, `staging_rds_username`
- `staging_redis_primary_endpoint_address`, `staging_redis_port`

They do not include passwords, tokens, or full connection URLs. Terraform state
will contain normal Terraform resource metadata and those non-secret outputs;
it must not contain the final `DATABASE_URL`, final `REDIS_URL`, DB password,
or Redis credentials from the post-apply sync.

Run the validation dry-run first:

```sh
set +x
AWS_PROFILE="<staging-provisioning-profile>" \
AWS_REGION="eu-west-2" \
node scripts/sync-staging-runtime-secrets.mjs --dry-run
```

The equivalent non-mutating npm wrapper is
`npm run check:staging-runtime-secret-sync`; use it only after apply has created
the staging endpoints.

If the dry-run evidence is clean and the human apply approval record authorizes
post-apply secret sync, update the two runtime secrets:

```sh
set +x
AWS_PROFILE="<staging-provisioning-profile>" \
AWS_REGION="eu-west-2" \
MSCQR_STAGING_SECRET_SYNC_ENABLED=true \
MSCQR_STAGING_SECRET_SYNC_CONFIRM=MSCQR_UPDATE_STAGING_RUNTIME_SECRETS \
node scripts/sync-staging-runtime-secrets.mjs --sync-secrets
```

`DATABASE_URL` is constructed in memory from staging RDS host, port, database
name, username, and a password source. The password source is, in order:
`MSCQR_STAGING_DATABASE_PASSWORD`, `MSCQR_STAGING_DATABASE_PASSWORD_SECRET_ID`,
or the RDS-managed master user secret returned by `describe-db-instances`.
The final URL is written only to Secrets Manager and is never printed.

`REDIS_URL` is constructed in memory from the staging Valkey primary endpoint
and port. Terraform does not configure Redis auth yet, so the first staging
URL is unauthenticated unless `MSCQR_STAGING_REDIS_PASSWORD` is explicitly
provided by an approved operator flow. The script still refuses production-
looking hosts and never prints a credential-bearing Redis URL.

After secrets are updated, force a new staging ECS deployment only with the
separate redeploy approval gate:

```sh
set +x
AWS_PROFILE="<staging-provisioning-profile>" \
AWS_REGION="eu-west-2" \
MSCQR_STAGING_ECS_REDEPLOY_ENABLED=true \
MSCQR_STAGING_ECS_REDEPLOY_CONFIRM=MSCQR_FORCE_STAGING_ECS_REDEPLOY \
node scripts/sync-staging-runtime-secrets.mjs --force-ecs-redeploy
```

Then run the staging health check against the reviewed staging ALB URL. Do not
use `mscqr.com` or any production hostname for staging health evidence.

## Required GitHub Checks

Before any staging Terraform plan/apply review continues, GitHub required checks
from PR #95 must be enabled on `main` either globally or through a path-scoped
ruleset. Required checks:

- `Staging Infra Validation/Terraform staging validate`
- `Staging Infra Validation/Staging IAM policy lint`

Configuration and verification steps are documented in
`documents/ops/MSCQR_GITHUB_BRANCH_PROTECTION_REQUIRED_CHECKS_2026-07-02.md`.

Use `terraform.tfvars.example` as a placeholder template only. Real private inputs must use only ignored local files (`staging.auto.tfvars` or `*.local.tfvars`) or `TF_VAR_*` environment variables, and must contain staging-only subnet IDs, reviewed operator CIDRs, an immutable staging backend image URI, and Secrets Manager ARNs under `mscqr/staging/*`. Preparation guidance is in `documents/ops/MSCQR_STAGING_PRIVATE_TFVARS_PREPARATION_2026-07-02.md`; cost evidence guidance is in `documents/ops/MSCQR_STAGING_COST_ESTIMATION_EVIDENCE_2026-07-02.md`.

The module models:

- ECS cluster `mscqr-staging-euw2-main`
- ECS service `mscqr-staging-backend-service-euw2`
- ECS task family `mscqr-staging-backend`
- ALB `mscqr-stg-alb-euw2`
- target group `mscqr-stg-backend-tg-euw2`
- log group `/ecs/mscqr-staging-backend`
- ECS Exec log group `/aws/ecs/mscqr-staging/exec`
- KMS key alias `alias/mscqr-staging-ecs-exec-logs`
- RDS instance `mscqr-staging-db`
- Valkey/Redis group `mscqr-staging-redis-euw2`
- S3 bucket `mscqr-staging-euw2-artifacts-<account_id>`
- IAM roles and staging-only security groups

ECS Exec task-role permissions are limited to the four SSM Messages channel actions required by ECS Exec, decrypt access to the staging ECS Exec KMS key for the managed agent, and CloudWatch Logs write permissions to `/aws/ecs/mscqr-staging/exec`. AWS does not support resource-level ARNs for the SSM Messages channel actions or `logs:DescribeLogGroups`, so those policy statements use `Resource = "*"` with the action lists constrained and `aws:RequestedRegion` pinned to `var.aws_region`.

Before any `terraform apply`, assume the reviewed least-privilege staging provisioning role and complete `documents/ops/MSCQR_STAGING_EXEC_AND_APPLY_APPROVAL_CHECKLIST_2026-07-02.md`, including reviewed plan evidence. Before any `ecs execute-command`, review the staging-only operator policy template at `documents/ops/iam/MSCQR_STAGING_ECS_EXEC_OPERATOR_POLICY_2026-07-02.json` and record the approval/evidence ID.

GitHub environment variables are intentionally documented outside this Terraform root and are not managed here.
