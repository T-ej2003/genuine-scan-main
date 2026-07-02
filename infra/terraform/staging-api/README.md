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

Review commands:

```sh
cd infra/terraform/staging-api
terraform init
terraform fmt -check
terraform validate
terraform plan -var-file=terraform.tfvars
```

Use `terraform.tfvars.example` as a placeholder template only. A real uncommitted `terraform.tfvars` must use staging-only subnet IDs, reviewed operator CIDRs, an immutable staging backend image URI, and Secrets Manager ARNs under `mscqr/staging/*`.

The module models:

- ECS cluster `mscqr-staging-euw2-main`
- ECS service `mscqr-staging-backend-service-euw2`
- ECS task family `mscqr-staging-backend`
- ALB `mscqr-stg-alb-euw2`
- target group `mscqr-stg-backend-tg-euw2`
- log group `/ecs/mscqr-staging-backend`
- RDS instance `mscqr-staging-db`
- Valkey/Redis group `mscqr-staging-redis-euw2`
- S3 bucket `mscqr-staging-euw2-artifacts-<account_id>`
- IAM roles and staging-only security groups

GitHub environment variables are intentionally documented outside this Terraform root and are not managed here.
