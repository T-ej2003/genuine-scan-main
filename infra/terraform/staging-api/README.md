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
- ECS Exec is enabled on the staging backend service only for controlled staging migration and seed execution. Operators still need explicit IAM permission for `ecs:ExecuteCommand`, and command activity must be reviewed through CloudTrail plus the backend CloudWatch log group and the dedicated ECS Exec CloudWatch log group.
- ECS Exec session logging is configured at the cluster level with `logging = "OVERRIDE"` and a staging KMS-backed CloudWatch log group at `/aws/ecs/mscqr-staging/exec`.
- S3 ECS Exec session logging is intentionally not enabled in this PR. Add it later only with a dedicated staging prefix, lifecycle policy, public access block, and KMS-backed bucket encryption reviewed against the same break-glass approval checklist.

Review commands:

```sh
cd infra/terraform/staging-api
terraform init -backend=false
terraform fmt -check
terraform validate
terraform plan -var-file=terraform.tfvars
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

## Required GitHub Checks

Before any staging Terraform plan/apply review continues, GitHub required checks
from PR #95 must be enabled on `main` either globally or through a path-scoped
ruleset. Required checks:

- `Staging Infra Validation/Terraform staging validate`
- `Staging Infra Validation/Staging IAM policy lint`

Configuration and verification steps are documented in
`documents/ops/MSCQR_GITHUB_BRANCH_PROTECTION_REQUIRED_CHECKS_2026-07-02.md`.

Use `terraform.tfvars.example` as a placeholder template only. A real uncommitted `terraform.tfvars` must use staging-only subnet IDs, reviewed operator CIDRs, an immutable staging backend image URI, and Secrets Manager ARNs under `mscqr/staging/*`.

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
